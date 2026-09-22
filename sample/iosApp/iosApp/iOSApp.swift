import SampleApp
import SwiftUI
import UIKit

@main
struct SiereAuthSampleApp: App {
    private let oidcConfiguration = OidcHostConfiguration()
    private let configuration = SupabaseHostConfiguration.fromEnvironment()

    var body: some Scene {
        WindowGroup {
            ComposeView(
                oidcHost: oidcConfiguration.host,
                supabaseHost: configuration?.host
            )
                .ignoresSafeArea()
                .onOpenURL { url in
                    _ = configuration?.host.handleOpenUrl(url: url.absoluteString)
                }
        }
    }
}

private struct ComposeView: UIViewControllerRepresentable {
    let oidcHost: IosOidcHost
    let supabaseHost: IosSupabaseHost?

    func makeUIViewController(context: Context) -> UIViewController {
        if let supabaseHost {
            return supabaseHost.makeViewController(oidcHost: oidcHost)
        }
        return oidcHost.makeViewController()
    }

    func updateUIViewController(_ uiViewController: UIViewController, context: Context) {}
}

private final class OidcHostConfiguration {
    let host = IosOidcHost {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first(where: \.isKeyWindow)
    }

    deinit {
        host.close()
    }
}

private final class SupabaseHostConfiguration {
    let host: IosSupabaseHost

    private init(host: IosSupabaseHost) {
        self.host = host
    }

    deinit {
        host.close()
    }

    static func fromEnvironment() -> SupabaseHostConfiguration? {
        let environment = ProcessInfo.processInfo.environment
        guard
            let url = environment["SIERE_SUPABASE_URL"], !url.isEmpty,
            let key = environment["SIERE_SUPABASE_PUBLISHABLE_KEY"], !key.isEmpty
        else {
            return nil
        }
        return SupabaseHostConfiguration(
            host: IosSupabaseHost(
                supabaseUrl: url,
                supabasePublishableKey: key
            )
        )
    }
}
