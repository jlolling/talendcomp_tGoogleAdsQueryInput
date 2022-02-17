/**
 * Copyright 2022 Jan Lolling jan.lolling@gmail.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.jlo.talendcomp.google.adsquery;

import java.awt.Desktop;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.ads.googleads.lib.GoogleAdsClient;
import com.google.ads.googleads.lib.GoogleAdsClient.Builder;
import com.google.ads.googleads.lib.GoogleAdsClient.Builder.ConfigPropertyKey;
import com.google.ads.googleads.v10.services.CustomerServiceClient;
import com.google.ads.googleads.v10.services.GoogleAdsRow;
import com.google.ads.googleads.v10.services.GoogleAdsServiceClient;
import com.google.ads.googleads.v10.services.ListAccessibleCustomersRequest;
import com.google.ads.googleads.v10.services.ListAccessibleCustomersResponse;
import com.google.ads.googleads.v10.services.SearchGoogleAdsStreamRequest;
import com.google.ads.googleads.v10.services.SearchGoogleAdsStreamResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.util.Key;
import com.google.api.gax.rpc.ServerStream;
import com.google.auth.oauth2.ClientId;
import com.google.auth.oauth2.UserAuthorizer;
import com.google.auth.oauth2.UserCredentials;
import com.google.common.base.MoreObjects;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

/**
 * This is a wrapper around the Google Ads API
 * @author jan.lolling@gmail.com
 *
 */
public class GoogleAdsQueryInput {

	private static final ImmutableList<String> SCOPES = ImmutableList.<String>builder()
			.add("https://www.googleapis.com/auth/adwords").build();
	private static final String OAUTH2_CALLBACK = "/oauth2callback";
	private GoogleAdsClient googleAdsClient = null;
	private Properties adsProperties = new Properties();
	private Long customerId = null;

	public void setupAdsPropertiesFromFile(String propFilePath) throws Exception {
		File f = new File(propFilePath);
		if (f.exists() == false) {
			throw new Exception("Properties file: " + f.getAbsolutePath() + " does not exist");
		}
		try (InputStream in = new FileInputStream(f)) {
			adsProperties.load(in);
		} catch (Exception e) {
			throw new Exception("Load auth properties from file: " + f.getAbsolutePath() + " failed.", e);
		}
		if (checkAndCompleteAdsProperties()) {
			// returns true if write back is needed
			writeAdsProperties(f);
		}
	}
	
	private boolean checkAndCompleteAdsProperties() throws Exception {
		if (checkIfUseServiceAccount()) {
			System.out.println("Check properties for completeness for service account...");
			checkStaticServiceAccountPropertiesKeys();
		} else {
			System.out.println("Check properties for completeness for clientId account...");
			checkStaticClientIdPropertiesKeys();
			// after that we have to get the refresh token.
			if (hasRefreshToken() == false) {
				// we need to get the refresh token, this means user interaction!
				System.out.println("Start fetching refresh token");
				fetchFreshToken();
				return true; // we have received a token and need to write it back
			}
		}
		return false; // we do not need to write the properties back
	}
	
	private void writeAdsProperties(File propFile) throws Exception {
		System.out.println("Start write back properties file: " + propFile.getAbsolutePath());
		if (adsProperties.isEmpty()) {
			throw new Exception("Ads-Properties are empty! This is an invalid state");
		}
		try (OutputStream out = new FileOutputStream(propFile)) {
			adsProperties.store(out, "Written back because refresh token received");
			out.flush();
			System.out.println("Properties file written");
		} catch (Exception e) {
			throw new Exception("Failed to write ads-properties to file: " + propFile.getAbsolutePath(), e);
		}
	}
	
	private boolean checkIfUseServiceAccount() throws Exception {
		String clientId = adsProperties.getProperty(ConfigPropertyKey.CLIENT_ID.getPropertyKey());
		if (clientId == null) {
			// we did not found a clientID, lets check if we have a service account
			String serviceAccount = adsProperties.getProperty(ConfigPropertyKey.SERVICE_ACCOUNT_USER.getPropertyKey());
			if (serviceAccount == null) {
				throw new Exception("Invalid properties found, neither properties for using clientId or service account found!");
			} else {
				return true;
			}
		} else {
			return false;
		}
	}

	private void checkStaticClientIdPropertiesKeys() throws Exception {
		String clientId = adsProperties.getProperty(ConfigPropertyKey.CLIENT_ID.getPropertyKey());
		if (clientId == null) {
			throw new Exception("Property: " + ConfigPropertyKey.CLIENT_ID.getPropertyKey() + " is missing");
		}
		String clientSecret = adsProperties.getProperty(ConfigPropertyKey.CLIENT_SECRET.getPropertyKey());
		if (clientSecret == null) {
			throw new Exception("Property: " + ConfigPropertyKey.CLIENT_SECRET.getPropertyKey() + " is missing");
		}
		String developerToken = adsProperties.getProperty(ConfigPropertyKey.DEVELOPER_TOKEN.getPropertyKey());
		if (developerToken == null) {
			throw new Exception("Property: " + ConfigPropertyKey.DEVELOPER_TOKEN.getPropertyKey() + " is missing");
		}
	}

	private void checkStaticServiceAccountPropertiesKeys() throws Exception {
		String serviceAccount = adsProperties.getProperty(ConfigPropertyKey.SERVICE_ACCOUNT_USER.getPropertyKey());
		if (serviceAccount == null) {
			throw new Exception("Property: " + ConfigPropertyKey.SERVICE_ACCOUNT_USER.getPropertyKey() + " is missing");
		}
		String serviceAcountSecretPath = adsProperties.getProperty(ConfigPropertyKey.SERVICE_ACCOUNT_SECRETS_PATH.getPropertyKey());
		if (serviceAcountSecretPath == null) {
			throw new Exception("Property: " + ConfigPropertyKey.SERVICE_ACCOUNT_SECRETS_PATH.getPropertyKey() + " is missing");
		}
	}

	private boolean hasRefreshToken() {
		String refreshToken = adsProperties.getProperty(ConfigPropertyKey.REFRESH_TOKEN.getPropertyKey());
		if (refreshToken == null || refreshToken.trim().isEmpty()) {
			return false;
		} else {
			return true;
		}
	}

	private void fetchFreshToken() throws Exception {
		String clientId = adsProperties.getProperty(ConfigPropertyKey.CLIENT_ID.getPropertyKey());
		String clientSecret = adsProperties.getProperty(ConfigPropertyKey.CLIENT_SECRET.getPropertyKey());
		// Creates an anti-forgery state token as described here:
		// https://developers.google.com/identity/protocols/OpenIDConnect#createxsrftoken
		String state = new BigInteger(130, new SecureRandom()).toString(32);
		// Creates an HTTP server that will listen for the OAuth2 callback request.
		URI baseUri;
		UserAuthorizer userAuthorizer;
		AuthorizationResponse authorizationResponse = null;
		System.out.println("Start Callback server on ....");
		try (SimpleCallbackServer simpleCallbackServer = new SimpleCallbackServer()) {
			userAuthorizer = UserAuthorizer.newBuilder()
								.setClientId(ClientId.of(clientId, clientSecret))
								.setScopes(SCOPES)
								.setCallbackUri(URI.create(OAUTH2_CALLBACK))
								.build();
			baseUri = URI.create("http://localhost:" + simpleCallbackServer.getLocalPort());
			if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
				URI uri = userAuthorizer.getAuthorizationUrl(null, state, baseUri).toURI();
				System.out.println("Start browser with uri=" + uri.toString());
				Desktop.getDesktop().browse(uri);
			} else {
				throw new Exception("Not possible to start a browser");
			}
			System.out.println("Wait for receiving oauth2 callback...");
			// Waits for the authorization code.
			simpleCallbackServer.accept();
			System.out.println("Received callback.");
			authorizationResponse = simpleCallbackServer.authorizationResponse;
		} catch (Exception e) {
			throw new Exception("Failed to receive OAuth callback", e);
		}

		if (authorizationResponse == null || authorizationResponse.code == null) {
			throw new NullPointerException(
					"OAuth2 callback did not contain an authorization code: " + authorizationResponse);
		}

		// Confirms that the state in the response matches the state token used to
		// generate the
		// authorization URL.
		if (!state.equals(authorizationResponse.state)) {
			throw new IllegalStateException("State does not match expected state");
		}

		// Exchanges the authorization code for credentials and print the refresh token.
		UserCredentials userCredentials = userAuthorizer.getCredentialsFromCode(authorizationResponse.code, baseUri);
		String token = userCredentials.getRefreshToken();
		if (token == null || token.trim().isEmpty()) {
			throw new Exception("No refresh token received for clientId: "+ clientId);
		}
		adsProperties.put(ConfigPropertyKey.REFRESH_TOKEN.getPropertyKey(), token);
	}

	/**
	 * Basic server that listens for the OAuth2 callback from the Web application
	 * flow.
	 */
	private static class SimpleCallbackServer extends ServerSocket {

		private AuthorizationResponse authorizationResponse;

		SimpleCallbackServer() throws IOException {
			// Passes a port # of zero so that a port will be automatically allocated.
			super(0);
		}

		/**
		 * Blocks until a connection is made to this server. After this method
		 * completes, the authorizationResponse of this server will be set, provided the
		 * request line is in the expected format.
		 */
		@Override
		public Socket accept() throws IOException {
			Socket socket = super.accept();

			try (BufferedReader in = new BufferedReader(
					new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {
				String callbackRequest = in.readLine();
				// Uses a regular expression to extract the request line from the first line of
				// the
				// callback request, e.g.:
				// GET /?code=AUTH_CODE&state=XYZ&scope=https://www.googleapis.com/auth/adwords
				// HTTP/1.1
				Pattern pattern = Pattern.compile("GET +([^ ]+)");
				Matcher matcher = pattern.matcher(Strings.nullToEmpty(callbackRequest));
				if (matcher.find()) {
					String relativeUrl = matcher.group(1);
					authorizationResponse = new AuthorizationResponse("http://localhost" + relativeUrl);
				}
				try (Writer outputWriter = new OutputStreamWriter(socket.getOutputStream())) {
					outputWriter.append("HTTP/1.1 ");
					outputWriter.append(Integer.toString(HttpStatusCodes.STATUS_CODE_OK));
					outputWriter.append(" OK\n");
					outputWriter.append("Content-Type: text/html\n\n");

					outputWriter.append("<b>");
					if (authorizationResponse.code != null) {
						outputWriter.append("Authorization code was successfully retrieved.");
					} else {
						outputWriter.append("Failed to retrieve authorization code.");
					}
				}
			}
			return socket;
		}
		
	}

	/**
	 * Response object with attributes corresponding to OAuth2 callback parameters.
	 */
	private static class AuthorizationResponse extends GenericUrl {

		/**
		 * The authorization code to exchange for an access token and (optionally) a
		 * refresh token.
		 */
		@Key
		String code;

		/** Error from the request or from the processing of the request. */
		@Key
		String error;

		/** State parameter from the callback request. */
		@Key
		String state;

		/**
		 * Constructs a new instance based on an absolute URL. All fields annotated with
		 * the {@link Key} annotation will be set if they are present in the URL.
		 *
		 * @param encodedUrl absolute URL with query parameters.
		 */
		public AuthorizationResponse(String encodedUrl) {
			super(encodedUrl);
		}

		@Override
		public String toString() {
			return MoreObjects.toStringHelper(getClass()).add("code", code).add("error", error).add("state", state)
					.toString();
		}
		
	}

	public void initiateClient() throws Exception {
		if (adsProperties.isEmpty()) {
			throw new Exception("Authentication properties not set or loaded!");
		}
		Builder builder = GoogleAdsClient.newBuilder();
		builder.fromProperties(adsProperties);
		googleAdsClient = builder.build();
		System.out.println("Google Ads Client version: " + googleAdsClient.getEndpoint());
	}
	
	public List<String> listAccessibleCustomers() throws Exception {
		List<String> customers = new ArrayList<>();
		try (CustomerServiceClient customerService = googleAdsClient.getLatestVersion().createCustomerServiceClient()) {
			ListAccessibleCustomersResponse response = customerService
					.listAccessibleCustomers(ListAccessibleCustomersRequest.newBuilder().build());

			System.out.printf("Total results: %d%n", response.getResourceNamesCount());
			for (String customerResourceName : response.getResourceNamesList()) {
				customers.add(customerResourceName);
			}
		}
		return customers;
	}

	public List<String> listCampaings() throws Exception {
		if (customerId == null) {
			throw new IllegalStateException("CustomerId is not set");
		}
		List<String> result = new ArrayList<>();
		try (GoogleAdsServiceClient googleAdsServiceClient = googleAdsClient.getLatestVersion()
				.createGoogleAdsServiceClient()) {
			String query = "SELECT campaign.id, campaign.name FROM campaign ORDER BY campaign.id";
			// Constructs the SearchGoogleAdsStreamRequest.
			SearchGoogleAdsStreamRequest request = SearchGoogleAdsStreamRequest.newBuilder()
					.setCustomerId(Long.toString(customerId)).setQuery(query).build();

			// Creates and issues a search Google Ads stream request that will retrieve all
			// campaigns.
			ServerStream<SearchGoogleAdsStreamResponse> stream = googleAdsServiceClient.searchStreamCallable()
					.call(request);

			// Iterates through and prints all of the results in the stream response.
			for (SearchGoogleAdsStreamResponse response : stream) {
				for (GoogleAdsRow googleAdsRow : response.getResultsList()) {
					result.add(googleAdsRow.getCampaign().getId() + "/" + googleAdsRow.getCampaign().getName());
				}
			}
		}
		return result;
	}
	
	public Long getCustomerId() {
		return customerId;
	}

	public void setCustomerId(String customerId) {
		if (customerId == null || customerId.trim().isEmpty()) {
			throw new IllegalArgumentException("customerId cannot be null or empty");
		}
		this.customerId = Long.valueOf(customerId.replace("-", ""));
	}

}