//
//  LogInViewModel.swift
//  passKeyDemo
//
//  Created by Vijaykrishna Jonnalagadda on 19/09/24.
//


import Foundation
import AuthenticationServices

class LoginViewModel: ObservableObject {
    
    @Published var isLoggedIn = false
    @Published var showSignInError = false
    private var accountManager = AccountManager()

    func signIn(anchor: ASPresentationAnchor, preferImmediatelyAvailableCredentials: Bool) {
        accountManager.signInWith(anchor: anchor, preferImmediatelyAvailableCredentials: preferImmediatelyAvailableCredentials)
        NotificationCenter.default.addObserver(forName: .UserSignedIn, object: nil, queue: .main) { _ in
            self.isLoggedIn = true
        }
        NotificationCenter.default.addObserver(forName: .ModalSignInSheetCanceled, object: nil, queue: .main) { _ in
            self.showSignInError = true
        }
    }

    func signUp(userName: String, anchor: ASPresentationAnchor) {
        accountManager.signUpWith(userName: userName, anchor: anchor)
        NotificationCenter.default.addObserver(forName: .UserSignedIn, object: nil, queue: .main) { _ in
            self.isLoggedIn = true
        }
        NotificationCenter.default.addObserver(forName: .ModalSignInSheetCanceled, object: nil, queue: .main) { _ in
            self.showSignInError = true
        }
    }
}
