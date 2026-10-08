// PhotoKit side of the driver (ARCHITECTURE §2.2–§2.8): collections, selection index, resource
// descriptors, export into the spool, inspection for the move guards, and the batch delete.
import Foundation
import IOSTCore
import IOSTSelection
import Photos

struct CollectionInfo: Identifiable, Hashable {
    /// "all" for Recents, otherwise the PHAssetCollection localIdentifier.
    let id: String
    let title: String
    let count: Int
}

enum PhotoLibrary {
    static var authorized: Bool { PHPhotoLibrary.authorizationStatus(for: .readWrite) == .authorized }
    static var limited: Bool { PHPhotoLibrary.authorizationStatus(for: .readWrite) == .limited }

    static func requestAccess(_ done: @escaping (PHAuthorizationStatus) -> Void) {
        PHPhotoLibrary.requestAuthorization(for: .readWrite) { s in DispatchQueue.main.async { done(s) } }
    }

    static func mediaType(_ section: Section) -> PHAssetMediaType { section == .videos ? .video : .image }

    static func options(_ section: Section) -> PHFetchOptions {
        let o = PHFetchOptions()
        o.sortDescriptors = [NSSortDescriptor(key: "creationDate", ascending: true)]
        o.predicate = NSPredicate(format: "mediaType == %d", mediaType(section).rawValue)
        return o
    }

    /// Recents first, then the built-in smart albums that have assets of this kind, then user albums.
    static func collections(_ section: Section) -> [CollectionInfo] {
        var out = [CollectionInfo(id: "all", title: "Recents", count: PHAsset.fetchAssets(with: options(section)).count)]
        let preferred: [PHAssetCollectionSubtype] = section == .photos
            ? [.smartAlbumFavorites, .smartAlbumScreenshots, .smartAlbumSelfPortraits, .smartAlbumLivePhotos,
               .smartAlbumDepthEffect, .smartAlbumPanoramas, .smartAlbumBursts, .smartAlbumLongExposures, .smartAlbumAnimated]
            : [.smartAlbumVideos, .smartAlbumSlomoVideos, .smartAlbumTimelapses, .smartAlbumFavorites]
        let skip: Set<PHAssetCollectionSubtype> = [.smartAlbumUserLibrary, .smartAlbumAllHidden, .smartAlbumRecentlyAdded]
        var smart: [(Int, CollectionInfo)] = []
        PHAssetCollection.fetchAssetCollections(with: .smartAlbum, subtype: .any, options: nil).enumerateObjects { c, _, _ in
            guard !skip.contains(c.assetCollectionSubtype) else { return }
            let n = PHAsset.fetchAssets(in: c, options: options(section)).count
            guard n > 0 else { return }
            let rank = preferred.firstIndex(of: c.assetCollectionSubtype) ?? preferred.count
            smart.append((rank, CollectionInfo(id: c.localIdentifier, title: c.localizedTitle ?? "Album", count: n)))
        }
        out += smart.sorted { ($0.0, $0.1.title) < ($1.0, $1.1.title) }.map(\.1)
        PHAssetCollection.fetchAssetCollections(with: .album, subtype: .albumRegular, options: nil).enumerateObjects { c, _, _ in
            let n = PHAsset.fetchAssets(in: c, options: options(section)).count
            if n > 0 { out.append(CollectionInfo(id: c.localIdentifier, title: c.localizedTitle ?? "Album", count: n)) }
        }
        return out
    }

    static func fetch(_ collection: String, _ section: Section) -> PHFetchResult<PHAsset> {
        if collection == "all" { return PHAsset.fetchAssets(with: options(section)) }
        guard let c = PHAssetCollection.fetchAssetCollections(withLocalIdentifiers: [collection], options: nil).firstObject
        else { return PHFetchResult() }
        return PHAsset.fetchAssets(in: c, options: options(section))
    }

    static func assets(_ ids: [AssetID]) -> [AssetID: PHAsset] {
        var out: [AssetID: PHAsset] = [:]
        let o = PHFetchOptions()
        o.includeAllBurstAssets = true
        o.includeHiddenAssets = true
        PHAsset.fetchAssets(withLocalIdentifiers: ids, options: o).enumerateObjects { a, _, _ in out[a.localIdentifier] = a }
        return out
    }

    // MARK: Descriptors (PROTOCOL §5.1, §5.2)

    static func typeName(_ t: PHAssetResourceType) -> String? {
        switch t {
        case .photo: "photo"
        case .video: "video"
        case .audio: "audio"
        case .alternatePhoto: "alternate_photo"
        case .fullSizePhoto: "full_size_photo"
        case .fullSizeVideo: "full_size_video"
        case .adjustmentData: "adjustment_data"
        case .adjustmentBasePhoto: "adjustment_base_photo"
        case .pairedVideo: "paired_video"
        case .fullSizePairedVideo: "full_size_paired_video"
        case .adjustmentBasePairedVideo: "adjustment_base_paired_video"
        case .adjustmentBaseVideo: "adjustment_base_video"
        case .photoProxy: nil // never an original
        @unknown default: "unknown_\(t.rawValue)"
        }
    }

    /// Resources with their protocol keys ("<type>#<n>").
    static func keyedResources(_ asset: PHAsset) -> [(key: ResKey, type: String, resource: PHAssetResource)] {
        var counts: [String: Int] = [:]
        return PHAssetResource.assetResources(for: asset).compactMap { r in
            guard let t = typeName(r.type) else { return nil }
            let n = counts[t, default: 0]
            counts[t] = n + 1
            return ("\(t)#\(n)", t, r)
        }
    }

    /// Best effort (private KVC, harmless for a sideloaded app); the protocol never depends on it.
    static func sizeHint(_ r: PHAssetResource) -> UInt64? {
        // value(forKey:) on a missing key raises: check first, so a future iOS can't crash us.
        guard r.responds(to: NSSelectorFromString("fileSize")) else { return nil }
        return (r.value(forKey: "fileSize") as? NSNumber)?.uint64Value
    }

    static func locallyAvailable(_ r: PHAssetResource) -> Bool {
        guard r.responds(to: NSSelectorFromString("locallyAvailable")) else { return true }
        return (r.value(forKey: "locallyAvailable") as? Bool) ?? true
    }

    static func descriptor(_ a: PHAsset) -> AssetDescriptor {
        let created = a.creationDate ?? Date(timeIntervalSince1970: 0)
        let loc = a.location.map {
            FingerprintLocationCodable(lat: $0.coordinate.latitude, lon: $0.coordinate.longitude,
                                       alt: $0.verticalAccuracy >= 0 ? $0.altitude : nil)
        }
        let meta = AssetMeta(createdMs: Int64(created.timeIntervalSince1970 * 1000),
                             tzMin: Int32(TimeZone.current.secondsFromGMT(for: created) / 60), fav: a.isFavorite, loc: loc)
        var subtypes: [String] = []
        if a.mediaSubtypes.contains(.photoLive) { subtypes.append("live") }
        if a.mediaSubtypes.contains(.photoHDR) { subtypes.append("hdr") }
        if a.mediaSubtypes.contains(.photoScreenshot) { subtypes.append("screenshot") }
        if a.mediaSubtypes.contains(.photoDepthEffect) { subtypes.append("portrait") }
        if a.mediaSubtypes.contains(.videoHighFrameRate) { subtypes.append("slomo") }
        return AssetDescriptor(
            id: a.localIdentifier, kind: a.mediaType == .video ? .videos : .photos, meta: meta,
            modifiedMs: Int64((a.modificationDate ?? created).timeIntervalSince1970 * 1000),
            w: a.pixelWidth, h: a.pixelHeight, durMs: a.mediaType == .video ? Int64(a.duration * 1000) : nil,
            burstID: a.burstIdentifier, subtypes: subtypes,
            resources: keyedResources(a).map {
                ResourceDescriptor(key: $0.key, type: $0.type, uti: $0.resource.uniformTypeIdentifier,
                                   name: $0.resource.originalFilename, sizeHint: sizeHint($0.resource))
            })
    }

    // MARK: Export (ARCHITECTURE §2.6): writeData into "<file>.tmp", rename on success

    static func export(_ id: AssetID, key: ResKey, to url: URL, done: @escaping (Result<UInt64, ExportFailure>) -> Void) {
        guard let asset = assets([id])[id] else { return done(.failure(.assetGone)) }
        guard let r = keyedResources(asset).first(where: { $0.key == key })?.resource else { return done(.failure(.assetGone)) }
        if let size = try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber {
            return done(.success(size.uint64Value)) // already spooled before a crash or reconnect
        }
        let tmp = url.appendingPathExtension("tmp")
        try? FileManager.default.removeItem(at: tmp)
        let o = PHAssetResourceRequestOptions()
        o.isNetworkAccessAllowed = false // iCloud Photos must be off; never download (§2.6)
        PHAssetResourceManager.default().writeData(for: r, toFile: tmp, options: o) { error in
            if let error = error as NSError? {
                try? FileManager.default.removeItem(at: tmp)
                if error.domain == PHPhotosErrorDomain, error.code == PHPhotosError.networkAccessRequired.rawValue {
                    return done(.failure(.notLocal))
                }
                if error.domain == NSCocoaErrorDomain, error.code == NSFileWriteOutOfSpaceError {
                    return done(.failure(.noSpace))
                }
                return done(.failure(.readError))
            }
            do {
                try FileManager.default.moveItem(at: tmp, to: url)
                let size = (try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.uint64Value ?? 0
                done(.success(size))
            } catch {
                done(.failure(.readError))
            }
        }
    }

    // MARK: Move phase

    /// Fresh look at assets for VERIFY and the pre-delete guards (PROTOCOL §8.4).
    static func inspect(_ ids: [AssetID], wantFingerprint: Set<AssetID>, scratch: URL,
                        done: @escaping ([AssetCurrentState]) -> Void) {
        let found = assets(ids)
        var states: [AssetCurrentState] = []
        let group = DispatchGroup()
        let lock = NSLock()
        for id in ids {
            guard let a = found[id] else {
                states.append(AssetCurrentState(id: id, exists: false, canDelete: false, isLocal: false, modifiedMs: 0, fingerprint: nil))
                continue
            }
            let res = keyedResources(a)
            let modified = Int64((a.modificationDate ?? Date()).timeIntervalSince1970 * 1000)
            let canDelete = a.canPerform(.delete) && a.sourceType.contains(.typeUserLibrary)
            let isLocal = res.allSatisfy { locallyAvailable($0.resource) }
            guard wantFingerprint.contains(id) else {
                states.append(AssetCurrentState(id: id, exists: true, canDelete: canDelete, isLocal: isLocal, modifiedMs: modified, fingerprint: nil))
                continue
            }
            let d = descriptor(a)
            var adj: [String: [UInt8]] = [:]
            for r in res where r.type == "adjustment_data" {
                group.enter()
                var bytes = Data()
                let o = PHAssetResourceRequestOptions()
                o.isNetworkAccessAllowed = false
                PHAssetResourceManager.default().requestData(for: r.resource, options: o, dataReceivedHandler: { bytes.append($0) }) { _ in
                    lock.lock()
                    adj[r.key] = IOSTCrypto.sha256(bytes)
                    lock.unlock()
                    group.leave()
                }
            }
            group.wait()
            // Sizes: the KVC hint, else the spooled file's size is not available here; an
            // unknown size makes the core transfer the resource first (no blind deletes).
            let sizes = res.map { (key: $0.key, size: sizeHint($0.resource) ?? 0) }
            let fp = FingerprintInput(createdMs: d.meta.createdMs, fav: d.meta.fav, loc: d.meta.loc.map {
                FingerprintLocation(lat: $0.lat, lon: $0.lon, alt: $0.alt)
            }, resources: sizes, adjustmentSHA256: adj)
            states.append(AssetCurrentState(id: id, exists: true, canDelete: canDelete, isLocal: isLocal, modifiedMs: modified, fingerprint: fp))
        }
        _ = scratch
        done(states)
    }

    /// ONE performChanges for the whole batch: one system prompt (ARCHITECTURE §2.8).
    static func delete(_ ids: [AssetID], done: @escaping (DeleteOutcome) -> Void) {
        let fetched = PHAsset.fetchAssets(withLocalIdentifiers: ids, options: nil)
        PHPhotoLibrary.shared().performChanges({
            PHAssetChangeRequest.deleteAssets(fetched)
        }) { ok, error in
            if ok { return done(.success) }
            if let e = error as NSError?, e.domain == PHPhotosErrorDomain, e.code == PHPhotosError.userCancelled.rawValue {
                return done(.userCancelled)
            }
            done(.error(error?.localizedDescription ?? "delete failed"))
        }
    }
}

/// A collection's fetch result as the selection's AssetIndex. The id → index map is built lazily
/// (only boundary and tap lookups need it).
final class FetchIndex: AssetIndex {
    let result: PHFetchResult<PHAsset>
    private var ids: [AssetID]?
    private var positions: [AssetID: Int]?

    init(_ result: PHFetchResult<PHAsset>) {
        self.result = result
    }

    var count: Int { result.count }
    func id(at i: Int) -> AssetID { result.object(at: i).localIdentifier }
    func createdMs(at i: Int) -> Int64 { Int64((result.object(at: i).creationDate ?? .distantPast).timeIntervalSince1970 * 1000) }

    func index(of id: AssetID) -> Int? {
        if positions == nil {
            var map: [AssetID: Int] = [:]
            map.reserveCapacity(result.count)
            result.enumerateObjects { a, i, _ in map[a.localIdentifier] = i }
            positions = map
        }
        return positions?[id]
    }
}
