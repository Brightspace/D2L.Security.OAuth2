namespace D2L.Security.AuthTokenProvisioning.Tests.Utilities {
	internal static class TestParameters {
		
		internal static ProvisioningParameters MakeValidProvisioningParams() {
			ProvisioningParameters provisioningParams = new ProvisioningParameters(
				TestCredentials.LMS.CLIENT_ID,
				TestCredentials.LMS.CLIENT_SECRET,
				new string[] { TestCredentials.LOReSScopes.MANAGE },
				"sometenantid",
				"sometenanturl"
				);

			return provisioningParams;
		}
	}
}
