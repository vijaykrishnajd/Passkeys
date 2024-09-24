//
//  NewLogInView.swift
//  passKeyDemo
//
//  Created by Vijaykrishna Jonnalagadda on 19/09/24.
//

import SwiftUI

struct NewLoginView: View {
    
    @StateObject private var viewModel = LoginViewModel()
    @State private var userName: String = ""
    @State private var password: String = ""
    
    var body: some View {
        
        VStack {
            
            TextField("Username", text: $userName)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()
                .textContentType(.username)
            
            SecureField("Password", text: $password)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()
                .textContentType(.password)

            Button("Sign In") {
                // Use the current window's scene to get the anchor
                if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                   let window = windowScene.windows.first {
                    viewModel.signIn(anchor: window, preferImmediatelyAvailableCredentials: true)
                }
            }
            
            .padding()

            Button("Sign Up") {
                // Use the current window's scene to get the anchor
                if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                   let window = windowScene.windows.first {
                    viewModel.signUp(userName: userName, anchor: window)
                }
            }
            .padding()

            if viewModel.showSignInError {
                Text("Sign-in was canceled or failed.")
                    .foregroundColor(.red)
                    .padding()
            }

            if viewModel.isLoggedIn {
                Text("Welcome! You are logged in.")
            }
        }
        .padding()
    }
}
