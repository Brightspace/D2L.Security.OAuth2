namespace D2L.Security.RequestAuthentication.Tests.Utilities {
	
	internal static class TestTokens {

		/// <summary>
		/// Valid
		/// {
		///		"uid":169,
		///		"tid":"00000000-0000-0000-0000-000000000000",
		///		"xt":"abc",
		///		"exp":1621858476,
		///		"iss":"https://api.d2l.com/auth",
		///		"scope":"https://api.brightspace.com/auth/lores.manage"
		///	}
		/// </summary>
		internal const string VALID_NO_XSRF_JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjE2OSwidGlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwieHQiOiJhYmMiLCJleHAiOjE2MjE4NTg0NzYsImlzcyI6Imh0dHBzOi8vYXBpLmQybC5jb20vYXV0aCIsInNjb3BlIjoiaHR0cHM6Ly9hcGkuYnJpZ2h0c3BhY2UuY29tL2F1dGgvbG9yZXMubWFuYWdlIn0.iTfa5PZCaMN0b_-XZn1ptcDp09IekLaGv0Lsn4YDnrX-K-Q7h9LxEgRtDvehRQH6t7qFxrHzEWxgTz8WKCQjI9zJpU9s6sxpl02QtfRzY3GMESHgqjUY5he8Fasz0R06iBBU6rIeWjU8G9ku3DJCjSwTqChlOuOYHxJE9_L93hv9a7x-W8G-KWeLmUEZIUmgOI_t58YE2ET7e_APguI_BLsXOvQPsO8uYA5vFRW9fm7hIxfXFsc5ysjYDrhmPLjAVlRbDUsV39Y89A5QWm71Efs4FbuxJoV2eNE8TQRzY8eaLA5CHEL2Dap7Zy768QVn_cjLHPjOH04NxzaA2XqAWA";
	}
}
