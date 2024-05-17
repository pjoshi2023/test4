/*
 * Copyright 2024 Curity AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.curity.identityserver.plugins.authenticator.config


import se.curity.identityserver.sdk.config.Configuration
import se.curity.identityserver.sdk.config.annotation.DefaultBoolean
import se.curity.identityserver.sdk.config.annotation.DefaultService
import se.curity.identityserver.sdk.config.annotation.Description
import se.curity.identityserver.sdk.service.ExceptionFactory
import se.curity.identityserver.sdk.service.HttpClient
import se.curity.identityserver.sdk.service.Json
import se.curity.identityserver.sdk.service.SessionManager
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider
import java.util.Optional

interface OidcClaimsSupportAuthenticatorPluginConfig : Configuration {
    @Description("Client id")
    fun getClientId(): String

    @Description("The issuer uri, used to collect endpoint information and signing keys")
    fun getIssuer(): String

    @Description("Scopes to request from provider")
    fun getScope(): List<String>

    @Description("The Authentication Context Class Reference (ACR) or authentication method that should be sent in the request to the OpenID Server")
    fun getAuthenticationContextClassReference(): Optional<String>

    @Description("The HTTP client with any proxy and TLS settings that will be used to connect to the provider")
    @DefaultService
    fun getHttpClient(): HttpClient

    @Description("The claims that are returned at the userinfo endpoint and in the ID token")
    fun getClaims(): Optional<String>

    @Description("Fetch claims from the userinfo endpoint")
    @DefaultBoolean(false)
    fun getFetchUserInfo():Boolean

    fun getSessionManager(): SessionManager

    fun getExceptionFactory(): ExceptionFactory

    fun getAuthenticatorInformationProvider(): AuthenticatorInformationProvider

    fun getJson(): Json
}
