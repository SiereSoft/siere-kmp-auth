// swift-tools-version: 5.9
import PackageDescription
let package = Package(
  name: "dev_gitlive_firebase_auth_3_0_0_alpha01_siere_37da67e3",
  platforms: [
    .iOS("15.0")
  ],
  products: [
    .library(
      name: "dev_gitlive_firebase_auth_3_0_0_alpha01_siere_37da67e3",
      type: .none,
      targets: ["dev_gitlive_firebase_auth_3_0_0_alpha01_siere_37da67e3"]
    )
  ],
  dependencies: [
    .package(
      url: "https://github.com/firebase/firebase-ios-sdk.git",
      from: "12.17.0"
    )
  ],
  targets: [
    .target(
      name: "dev_gitlive_firebase_auth_3_0_0_alpha01_siere_37da67e3",
      dependencies: [
        .product(
          name: "FirebaseAuth",
          package: "firebase-ios-sdk"
        )
      ]
    )
  ]
)
