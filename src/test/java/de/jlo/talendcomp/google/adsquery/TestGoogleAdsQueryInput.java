package de.jlo.talendcomp.google.adsquery;

import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

public class TestGoogleAdsQueryInput {
	
	private static String testPropertiesFileClientIdAccount = System.getProperty("user.home") + "/test_google_ads_clientId.properties";
	
	@Test
	public void testLoadProperties() throws Exception {
		GoogleAdsQueryInput g = new GoogleAdsQueryInput();
		g.setupAdsPropertiesFromFile(testPropertiesFileClientIdAccount);
		g.initiateClient();
		assertTrue(true);
	}

	@Test
	public void testGetAccessibleCustomers() throws Exception {
		GoogleAdsQueryInput g = new GoogleAdsQueryInput();
		g.setupAdsPropertiesFromFile(testPropertiesFileClientIdAccount);
		g.initiateClient();
		List<String> result = g.listAccessibleCustomers();
		for (String c : result) {
			System.out.println(c);
		}
		
	}

	@Test
	public void testGetCampaingns() throws Exception {
		GoogleAdsQueryInput g = new GoogleAdsQueryInput();
		g.setupAdsPropertiesFromFile(testPropertiesFileClientIdAccount);
		g.initiateClient();
		g.setCustomerId("725-485-2915");
		List<String> result = g.listCampaings();
		for (String c : result) {
			System.out.println(c);
		}
	}

}
