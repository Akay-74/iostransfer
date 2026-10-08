import IOSTCore
import IOSTSelection
import Photos
import SwiftUI
import UIKit

/// UIKit grid (ARCHITECTURE §2.4): UICollectionView + PHCachingImageManager, which stays smooth at
/// 50k+ assets; SwiftUI LazyVGrid does not.
struct GridRepresentable: UIViewControllerRepresentable {
    @EnvironmentObject var library: LibraryModel
    let collection: String
    let section: MediaSection
    let rangeMode: Bool
    @Binding var rangeStart: Int?

    func makeUIViewController(context: Context) -> GridController {
        let c = GridController(fetch: PhotoLibrary.fetch(collection, section))
        configure(c)
        return c
    }

    func updateUIViewController(_ c: GridController, context: Context) {
        configure(c)
        c.refreshVisible()
    }

    private func configure(_ c: GridController) {
        let lib = library, coll = collection, sec = section
        let start = $rangeStart
        c.isSelected = { i, idx in lib.selection(sec).contains(i, in: coll, idx) }
        c.rangeStart = rangeStart
        c.onTap = { i, idx in
            if rangeMode {
                if let s = start.wrappedValue {
                    lib.update(sec) { $0.applyRange(from: s, to: i, in: coll, idx) }
                    start.wrappedValue = nil
                } else {
                    start.wrappedValue = i
                }
            } else {
                lib.update(sec) { $0.toggle(idx.id(at: i), at: i, in: coll, idx) }
            }
        }
    }
}

final class GridController: UICollectionViewController {
    private let fetch: PHFetchResult<PHAsset>
    private let index: FetchIndex
    private let images = PHCachingImageManager()
    private var cellSize = CGSize(width: 90, height: 90)
    private var didInitialScroll = false
    var isSelected: (Int, FetchIndex) -> Bool = { _, _ in false }
    var onTap: (Int, FetchIndex) -> Void = { _, _ in }
    var rangeStart: Int?

    init(fetch: PHFetchResult<PHAsset>) {
        self.fetch = fetch
        index = FetchIndex(fetch)
        let layout = UICollectionViewFlowLayout()
        layout.minimumInteritemSpacing = 2
        layout.minimumLineSpacing = 2
        super.init(collectionViewLayout: layout)
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    override func viewDidLoad() {
        super.viewDidLoad()
        collectionView.register(Cell.self, forCellWithReuseIdentifier: "c")
        collectionView.backgroundColor = .systemBackground
        images.allowsCachingHighQualityImages = false
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        let w = (collectionView.bounds.width - 6) / 4
        cellSize = CGSize(width: w, height: w)
        (collectionViewLayout as? UICollectionViewFlowLayout)?.itemSize = cellSize
        if fetch.count > 0, !didInitialScroll {
            didInitialScroll = true
            // Newest at the bottom, like Photos (once; later layouts must not move the user).
            collectionView.scrollToItem(at: IndexPath(item: fetch.count - 1, section: 0), at: .bottom, animated: false)
        }
    }

    func refreshVisible() {
        for ip in collectionView.indexPathsForVisibleItems {
            (collectionView.cellForItem(at: ip) as? Cell)?.mark(selected: isSelected(ip.item, index), start: ip.item == rangeStart)
        }
    }

    override func collectionView(_: UICollectionView, numberOfItemsInSection _: Int) -> Int { fetch.count }

    override func collectionView(_ cv: UICollectionView, cellForItemAt ip: IndexPath) -> UICollectionViewCell {
        let cell = cv.dequeueReusableCell(withReuseIdentifier: "c", for: ip) as! Cell
        let asset = fetch.object(at: ip.item)
        cell.assetID = asset.localIdentifier
        let scale = UIScreen.main.scale
        let opts = PHImageRequestOptions()
        opts.deliveryMode = .opportunistic
        opts.isNetworkAccessAllowed = false
        images.requestImage(for: asset, targetSize: CGSize(width: cellSize.width * scale, height: cellSize.height * scale),
                            contentMode: .aspectFill, options: opts) { img, _ in
            if cell.assetID == asset.localIdentifier { cell.image.image = img }
        }
        cell.video.isHidden = asset.mediaType != .video
        cell.mark(selected: isSelected(ip.item, index), start: ip.item == rangeStart)
        return cell
    }

    override func collectionView(_: UICollectionView, didSelectItemAt ip: IndexPath) {
        onTap(ip.item, index)
    }

    final class Cell: UICollectionViewCell {
        let image = UIImageView()
        let check = UIImageView(image: UIImage(systemName: "checkmark.circle.fill"))
        let video = UIImageView(image: UIImage(systemName: "video.fill"))
        var assetID = ""

        override init(frame: CGRect) {
            super.init(frame: frame)
            image.contentMode = .scaleAspectFill
            image.clipsToBounds = true
            check.tintColor = .systemBlue
            check.backgroundColor = .white
            check.layer.cornerRadius = 11
            video.tintColor = .white
            for v in [image, check, video] {
                v.translatesAutoresizingMaskIntoConstraints = false
                contentView.addSubview(v)
            }
            NSLayoutConstraint.activate([
                image.topAnchor.constraint(equalTo: contentView.topAnchor),
                image.bottomAnchor.constraint(equalTo: contentView.bottomAnchor),
                image.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
                image.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
                check.widthAnchor.constraint(equalToConstant: 22), check.heightAnchor.constraint(equalToConstant: 22),
                check.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -4),
                check.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -4),
                video.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 4),
                video.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -4),
            ])
        }

        required init?(coder: NSCoder) { fatalError("not used") }

        func mark(selected: Bool, start: Bool) {
            check.isHidden = !selected
            image.alpha = selected ? 0.75 : 1
            contentView.layer.borderWidth = start ? 3 : 0
            contentView.layer.borderColor = UIColor.systemOrange.cgColor
        }

        override func prepareForReuse() {
            super.prepareForReuse()
            image.image = nil
        }
    }
}
