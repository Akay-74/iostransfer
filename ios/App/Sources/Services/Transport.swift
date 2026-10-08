// TLS 1.3 connection to the PC (PROTOCOL §1.1): ALPN iost/1, SPKI-pinned P-256 key, Bonjour
// discovery by pcid with the QR's IP addresses as fallback.
import Foundation
import IOSTCore
import Network
import Security

final class Transport {
    /// Events for the session driver, delivered on `queue`.
    enum Signal {
        case up
        case received([UInt8])
        case sent(token: UInt64)
        case down(String)
    }

    private let queue: DispatchQueue
    private let onSignal: (Signal) -> Void
    private var connection: NWConnection?
    private var browser: NWBrowser?
    private var bonjourEndpoint: NWEndpoint?
    private var generation = 0

    init(queue: DispatchQueue, onSignal: @escaping (Signal) -> Void) {
        self.queue = queue
        self.onSignal = onSignal
    }

    /// Watch for the PC's Bonjour advertisement (also triggers the Local Network prompt).
    func startBrowsing(pcID: String) {
        guard browser == nil else { return }
        let b = NWBrowser(for: .bonjourWithTXTRecord(type: "_iostransfer._tcp", domain: nil), using: .tcp)
        b.browseResultsChangedHandler = { [weak self] results, _ in
            for r in results {
                if case let .bonjour(txt) = r.metadata, txt["pcid"]?.lowercased() == pcID.lowercased() {
                    self?.bonjourEndpoint = r.endpoint
                }
            }
        }
        b.start(queue: queue)
        browser = b
    }

    func stopBrowsing() {
        browser?.cancel()
        browser = nil
    }

    /// Try Bonjour first, then each QR address; 5 s per candidate.
    func connect(hosts: [String], port: UInt16, pin: [UInt8]) {
        cancel()
        generation += 1
        var candidates: [NWEndpoint] = []
        if let e = bonjourEndpoint { candidates.append(e) }
        if let p = NWEndpoint.Port(rawValue: port) {
            candidates += hosts.map { .hostPort(host: NWEndpoint.Host($0), port: p) }
        }
        attempt(candidates, pin: pin, generation: generation)
    }

    private func attempt(_ candidates: [NWEndpoint], pin: [UInt8], generation gen: Int) {
        guard gen == generation else { return }
        guard let endpoint = candidates.first else { return onSignal(.down("PC not reachable on this network")) }
        let c = NWConnection(to: endpoint, using: Self.parameters(pin: pin, queue: queue))
        connection = c
        var settled = false
        let timeout = DispatchWorkItem { [weak self] in
            guard !settled else { return }
            settled = true
            c.cancel()
            self?.attempt(Array(candidates.dropFirst()), pin: pin, generation: gen)
        }
        queue.asyncAfter(deadline: .now() + 5, execute: timeout)
        c.stateUpdateHandler = { [weak self] state in
            guard let self, gen == self.generation else { return }
            switch state {
            case .ready:
                guard !settled else { return }
                settled = true
                timeout.cancel()
                self.onSignal(.up)
                self.receive(c, gen)
            case .failed(let e):
                if !settled {
                    settled = true
                    timeout.cancel()
                    self.attempt(Array(candidates.dropFirst()), pin: pin, generation: gen)
                } else {
                    self.onSignal(.down(e.localizedDescription))
                }
            case .cancelled where settled:
                break
            default:
                break
            }
        }
        c.start(queue: queue)
    }

    private func receive(_ c: NWConnection, _ gen: Int) {
        c.receive(minimumIncompleteLength: 1, maximumLength: 256 * 1024) { [weak self] data, _, complete, error in
            guard let self, gen == self.generation else { return }
            if let data, !data.isEmpty { self.onSignal(.received([UInt8](data))) }
            if complete || error != nil {
                self.generation += 1
                c.cancel()
                self.onSignal(.down(error?.localizedDescription ?? "PC closed the connection"))
                return
            }
            self.receive(c, gen)
        }
    }

    func send(_ bytes: [UInt8], token: UInt64) {
        guard let c = connection else { return }
        let gen = generation
        c.send(content: Data(bytes), completion: .contentProcessed { [weak self] error in
            guard let self, gen == self.generation else { return }
            if let error {
                self.generation += 1
                c.cancel()
                self.onSignal(.down(error.localizedDescription))
            } else {
                self.onSignal(.sent(token: token))
            }
        })
    }

    /// Send final bytes (BYE), then close.
    func close(after: [UInt8]?) {
        generation += 1
        guard let c = connection else { return }
        connection = nil
        if let after {
            c.send(content: Data(after), contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in
                c.cancel()
            })
            queue.asyncAfter(deadline: .now() + 2) { c.cancel() }
        } else {
            c.cancel()
        }
    }

    func cancel() {
        generation += 1
        connection?.cancel()
        connection = nil
    }

    // MARK: TLS profile

    static func parameters(pin: [UInt8], queue: DispatchQueue) -> NWParameters {
        let tls = NWProtocolTLS.Options()
        let opts = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(opts, .TLSv13)
        sec_protocol_options_add_tls_application_protocol(opts, "iost/1")
        sec_protocol_options_set_verify_block(opts, { _, trust, complete in
            complete(Self.matchesPin(trust: sec_trust_copy_ref(trust).takeRetainedValue(), pin: pin))
        }, queue)
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.connectionTimeout = 5
        return NWParameters(tls: tls, tcp: tcp)
    }

    /// SHA-256 over the P-256 SPKI of the leaf certificate, compared in constant time. Any other
    /// key type fails closed.
    static func matchesPin(trust: SecTrust, pin: [UInt8]) -> Bool {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first,
              let key = SecCertificateCopyKey(leaf),
              let point = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              let got = IOSTCrypto.spkiPin(p256Point: [UInt8](point))
        else { return false }
        return IOSTCrypto.constantTimeEqual(got, pin)
    }

    /// The pin of whatever certificate a PC presents, for the pairing screen's code check.
    static func pinOf(trust: SecTrust) -> [UInt8]? {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first,
              let key = SecCertificateCopyKey(leaf), let point = SecKeyCopyExternalRepresentation(key, nil) as Data?
        else { return nil }
        return IOSTCrypto.spkiPin(p256Point: [UInt8](point))
    }
}
