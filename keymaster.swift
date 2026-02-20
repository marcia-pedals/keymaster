// Keymaster, access Keychain secrets guarded by TouchID
//
import Foundation
import LocalAuthentication

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics

func setPassword(key: String, password: String) -> Bool {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecValueData as String: password
  ]

  let status = SecItemAdd(query as CFDictionary, nil)
  return status == errSecSuccess
}

func deletePassword(key: String) -> Bool {
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecMatchLimit as String: kSecMatchLimitOne
  ]
  let status = SecItemDelete(query as CFDictionary)
  return status == errSecSuccess
}

func getPassword(key: String) -> String? {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecReturnData as String: true
  ]
  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)

  guard status == errSecSuccess,
    let passwordData = item as? Data,
    let password = String(data: passwordData, encoding: String.Encoding.utf8)
  else { return nil }

  return password
}

func usage() {
  print("keymaster get [key1] [key2] ...")
  print("keymaster set [key] [secret]")
  print("keymaster delete [key]")
}

func main() {
  let inputArgs: [String] = Array(CommandLine.arguments.dropFirst())
  if (inputArgs.count < 2) {
    usage()
    exit(EXIT_FAILURE)
  }
  let action = inputArgs[0]

  if (action == "set") {
    guard inputArgs.count == 3 else {
      usage()
      exit(EXIT_FAILURE)
    }
    let key = inputArgs[1]
    let secret = inputArgs[2]
    guard setPassword(key: key, password: secret) else {
      print("Error setting password")
      exit(EXIT_FAILURE)
    }
    print("Key \(key) has been sucessfully set in the keychain")
    exit(EXIT_SUCCESS)
  }

  if (action == "delete") {
    guard inputArgs.count == 2 else {
      usage()
      exit(EXIT_FAILURE)
    }
    let key = inputArgs[1]
    guard deletePassword(key: key) else {
      print("Error deleting password")
      exit(EXIT_FAILURE)
    }
    print("Key \(key) has been sucessfully deleted from the keychain")
    exit(EXIT_SUCCESS)
  }

  if (action == "get") {
    let keys = Array(inputArgs.dropFirst())
    let keyList = keys.joined(separator: ", ")

    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0

    var error: NSError?
    guard context.canEvaluatePolicy(policy, error: &error) else {
      print("This Mac doesn't support deviceOwnerAuthenticationWithBiometrics")
      exit(EXIT_FAILURE)
    }

    context.evaluatePolicy(policy, localizedReason: "access passwords for: \(keyList)") { success, error in
      if success && error == nil {
        for key in keys {
          if let password = getPassword(key: key) {
            print("\(key)=\(password)")
          }
        }
        exit(EXIT_SUCCESS)
      } else {
        let errorDescription = error?.localizedDescription ?? "Unknown error"
        print("Error \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }
}

main()
