import SampleApp
import SwiftUI
import UIKit

@main
struct SiereAuthSampleApp: App {
    private let configuration = SupabaseHostConfiguration.fromEnvironment()

    var body: some Scene {
        WindowGroup {
            ComposeView(supabaseHost: configuration?.host)
                .ignoresSafeArea()
                .onOpenURL { url in
                    _ = configuration?.host.handleOpenUrl(url: url.absoluteString)
                }
        }
    }
}

private struct ComposeView: UIViewControllerRepresentable {
    let supabaseHost: IosSupabaseHost?

    func makeUIViewController(context: Context) -> UIViewController {
        if let supabaseHost {
            return supabaseHost.makeViewController()
        }
        return MainViewControllerKt.MainViewController(
            firebaseConfigured: false,
            googleSignIn: nil,
            supabaseBackendOrigin: nil,
            configuredSupabaseClient: nil
        )
    }

    func updateUIViewController(_ uiViewController: UIViewController, context: Context) {}
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
