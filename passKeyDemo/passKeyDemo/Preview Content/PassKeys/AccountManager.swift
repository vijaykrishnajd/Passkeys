//
//  AccountManager.swift
//  passKeyDemo
//
//  Created by Vijaykrishna Jonnalagadda on 19/09/24.
//

import AuthenticationServices
import Foundation
import os

extension NSNotification.Name {
    static let UserSignedIn = Notification.Name("UserSignedInNotification")
    static let ModalSignInSheetCanceled = Notification.Name("ModalSignInSheetCanceledNotification")
}

class AccountManager: NSObject, ASAuthorizationControllerPresentationContextProviding, ASAuthorizationControllerDelegate {
    
    let domain = "webcredentials:developerinsider.github.io"
    var authenticationAnchor: ASPresentationAnchor?
    var isPerformingModalRequest = false

    // Function to fetch challenge from the server
    private func fetchChallenge(completion: @escaping (Data?) -> Void) {
        // Replace this with actual network request to your server
        let challengeData = "unique_challenge".data(using: .utf8) // Example challenge
        completion(challengeData)
    }

    // Sign in using passkeys or passwords
    func signInWith(anchor: ASPresentationAnchor, preferImmediatelyAvailableCredentials: Bool) {
        
        self.authenticationAnchor = anchor
        let publicKeyCredentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)

        fetchChallenge { challenge in
            guard let challenge = challenge else {
                print("Failed to fetch challenge.")
                return
            }
            
            let assertionRequest = publicKeyCredentialProvider.createCredentialAssertionRequest(challenge: challenge)
            let passwordCredentialProvider = ASAuthorizationPasswordProvider()
            let passwordRequest = passwordCredentialProvider.createRequest()
            
            let authController = ASAuthorizationController(authorizationRequests: [assertionRequest, passwordRequest])
            authController.delegate = self
            authController.presentationContextProvider = self
            
            if preferImmediatelyAvailableCredentials {
                authController.performRequests(options: .preferImmediatelyAvailableCredentials)
            } else {
                authController.performRequests()
            }

            self.isPerformingModalRequest = true
        }
    }

    // Sign up using passkeys
    func signUpWith(userName: String, anchor: ASPresentationAnchor) {
        self.authenticationAnchor = anchor
        let publicKeyCredentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)

        fetchChallenge { challenge in
            guard let challenge = challenge else {
                print("Failed to fetch challenge.")
                return
            }

            let userID = Data(UUID().uuidString.utf8)
            let registrationRequest = publicKeyCredentialProvider.createCredentialRegistrationRequest(challenge: challenge, name: userName, userID: userID)
            
            let authController = ASAuthorizationController(authorizationRequests: [registrationRequest])
            authController.delegate = self
            authController.presentationContextProvider = self
            authController.performRequests()
            self.isPerformingModalRequest = true
        }
    }

    // Handle successful authorization
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        let logger = Logger()
        switch authorization.credential {
        case let credentialRegistration as ASAuthorizationPlatformPublicKeyCredentialRegistration:
            logger.log("A new passkey was registered: \(credentialRegistration)")
            // Verify attestationObject and clientDataJSON with your server
            // After server verifies registration, sign in the user
            didFinishSignIn()
            
        case let credentialAssertion as ASAuthorizationPlatformPublicKeyCredentialAssertion:
            logger.log("A passkey was used to sign in: \(credentialAssertion)")
            // Verify signature and clientDataJSON with your server
            didFinishSignIn()
            
        case let passwordCredential as ASPasswordCredential:
            logger.log("A password was provided: \(passwordCredential)")
            // Verify userName and password with your service
            didFinishSignIn()
            
        default:
            fatalError("Received unknown authorization type.")
        }

        isPerformingModalRequest = false
    }

    // Handle authorization errors
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        if let authError = error as? ASAuthorizationError {
            switch authError.code {
            case .canceled:
                print("Authorization was canceled by the user.")
            case .failed:
                print("Authorization failed.")
            case .invalidResponse:
                print("Invalid response from the authorization controller.")
            case .notHandled:
                print("Authorization request was not handled.")
            case .unknown:
                print("An unknown error occurred.")
            default:
                break
            }
        } else {
            print("Authorization failed with error: \(error.localizedDescription)")
        }

        let logger = Logger()
        guard let authorizationError = error as? ASAuthorizationError else {
            isPerformingModalRequest = false
            logger.error("Unexpected authorization error: \(error.localizedDescription)")
            return
        }

        if authorizationError.code == .canceled {
            logger.log("Request canceled.")
            if isPerformingModalRequest {
                didCancelModalSheet()
            }
        } else {
            logger.error("Error: \((error as NSError).userInfo)")
        }

        isPerformingModalRequest = false
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return authenticationAnchor!
    }

    func didFinishSignIn() {
        NotificationCenter.default.post(name: .UserSignedIn, object: nil)
    }

    func didCancelModalSheet() {
        NotificationCenter.default.post(name: .ModalSignInSheetCanceled, object: nil)
    }
}
