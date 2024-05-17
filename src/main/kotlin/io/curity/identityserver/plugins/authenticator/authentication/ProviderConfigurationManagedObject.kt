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

package io.curity.identityserver.plugins.authenticator.authentication

import io.curity.identityserver.plugins.authenticator.config.OidcClaimsSupportAuthenticatorPluginConfig
import org.jose4j.http.SimpleGet
import org.jose4j.http.SimpleResponse
import org.jose4j.jwk.HttpsJwks
import org.jose4j.jwt.consumer.JwtConsumer
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.errors.ErrorCode
import se.curity.identityserver.sdk.http.ContentType
import se.curity.identityserver.sdk.http.HttpResponse
import se.curity.identityserver.sdk.plugin.ManagedObject
import se.curity.identityserver.sdk.service.HttpClient
import java.lang.RuntimeException
import java.net.URI

class ProviderConfigurationManagedObject(private val _config: OidcClaimsSupportAuthenticatorPluginConfig) :
    ManagedObject<OidcClaimsSupportAuthenticatorPluginConfig>(_config) {
    companion object {
        private val _logger: Logger = LoggerFactory.getLogger(OidcClaimsSupportAuthenticatorPluginConfig::class.java)
    }

    private var metadata: DiscoveredProviderMetadata? = null

    lateinit var tokenEndpoint: URI

    lateinit var authorizeEndpoint: URI

    lateinit var userInfoEndpoint: URI

    private lateinit var _httpClient: HttpClient

    val jwtConsumer: JwtConsumer by lazy { createJwtConsumer() }

    /**
     * Since the http client is not available until runtime,
     * the request handlers will have to prepare the object with the HTTP client to use.
     *
     * @param httpClient from configuration
     */
    fun prepare(httpClient: HttpClient) = run {
        if (metadata != null) {
            return
        }
        _httpClient = httpClient
        metadata = DiscoveredProviderMetadata(_config, httpClient)
        authorizeEndpoint = metadata?.authorizeEndpoint ?: throw metadataNotFetchedException()
        tokenEndpoint = metadata?.tokenEndpoint ?: throw metadataNotFetchedException()
        userInfoEndpoint = metadata?.userInfoEndpoint ?: throw metadataNotFetchedException()
    }


    private fun createJwtConsumer(): JwtConsumer {
        val jwksUri = metadata?.jwksUri ?: throw metadataNotFetchedException()
        _logger.info("jwks_uri: $jwksUri")

        val httpsJwks = HttpsJwks(jwksUri.toString())
        httpsJwks.setSimpleHttpGet(SimpleGet { location: String ->
            try {
                val response = _httpClient.request(URI(location))
                    .accept("application/json")
                    .get().response()
                return@SimpleGet SimpleResponseAdapter(response)
            } catch (e: Exception) {
                throw _config.getExceptionFactory()
                    .internalServerException(ErrorCode.PLUGIN_ERROR, "Could not fetch JWKS")
            }
        })

        return JwtConsumerBuilder()
            .setRequireExpirationTime()
            .setSkipDefaultAudienceValidation()
            .setExpectedIssuer(_config.getIssuer())
            .setVerificationKeyResolver(HttpsJwksVerificationKeyResolver(httpsJwks))
            .build()
    }

    private fun metadataNotFetchedException(): RuntimeException = _config.getExceptionFactory()
        .internalServerException(ErrorCode.PLUGIN_ERROR, "Metadata not fetched")

    /**
     * Used to be able to use the SDK HttpClient with the Jose4j library, to keep the http settings in Curity config
     */
    class SimpleResponseAdapter(response: HttpResponse) : SimpleResponse {
        private val statusCode = response.statusCode()
        private val statusMessage = response.toString()
        private val headers = response.headers()
        private val body = response.body(HttpResponse.asString())

        override fun getStatusCode(): Int = statusCode

        override fun getStatusMessage(): String = statusMessage

        override fun getHeaderNames(): MutableCollection<String> = headers.map().keys

        override fun getHeaderValues(headerName: String): MutableList<String> = headers.allValues(headerName)

        override fun getBody(): String = body
    }

    /**
     * Discovers and holds the metadata of the OpenID provider
     */
    class DiscoveredProviderMetadata(config: OidcClaimsSupportAuthenticatorPluginConfig, httpClient: HttpClient) {
        companion object {
            private val _logger: Logger = LoggerFactory.getLogger(DiscoveredProviderMetadata::class.java)
        }

        private val _exceptionFactory = config.getExceptionFactory()

        val tokenEndpoint: URI
        val authorizeEndpoint: URI
        val userInfoEndpoint: URI
        val jwksUri: URI

        init {
            _logger.info("Discovering metadata")
            val providerConfiguration = fetchProviderConfiguration(config, httpClient)

            jwksUri = parseEndpoint(providerConfiguration, "jwks_uri")
            authorizeEndpoint = parseEndpoint(providerConfiguration, "authorization_endpoint")
            tokenEndpoint = parseEndpoint(providerConfiguration, "token_endpoint")
            userInfoEndpoint = parseEndpoint(providerConfiguration, "userinfo_endpoint")
        }

        private fun fetchProviderConfiguration(config: OidcClaimsSupportAuthenticatorPluginConfig, httpClient: HttpClient): Map<String,Any> {
            val discoveryResponse = httpClient
                .request(URI(config.getIssuer() + "/.well-known/openid-configuration"))
                .header("Accept", ContentType.JSON.contentType)
                .get().response()

            return discoveryResponse.body(HttpResponse.asJsonObject(config.getJson()))
        }

        private fun parseEndpoint(providerConfiguration: Map<String,Any>, key: String): URI {
            val endpoint = providerConfiguration[key] as? String
                ?: throw _exceptionFactory.configurationException("Could not get $key from provider metadata")

            return URI(endpoint)
        }
    }

}
