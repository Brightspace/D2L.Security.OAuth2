﻿namespace D2L.Security.RequestAuthentication.Tests.Utilities {
	
	internal static class TestTokens {

		internal static class ValidWithXsrfOneScope {
			internal const long Sub = 169;
			internal const string Tenantid = "00000000-0000-0000-0000-000000000000";
			internal const string Tenanturl = "http://lores.d2l";
			internal const string Xt = "abc";
			internal const long Exp = 1621858476;
			internal const string Iss = "https://api.d2l.com/auth";
			internal const string Scope = "https://api.brightspace.com/auth/lores.manage";

			internal const string Jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjE2OSwidGVuYW50dXJsIjoiaHR0cDovL2xvcmVzLmQybCIsInRlbmFudGlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwieHQiOiJhYmMiLCJleHAiOjE2MjE4NTg0NzYsImlzcyI6Imh0dHBzOi8vYXBpLmQybC5jb20vYXV0aCIsInNjb3BlIjoiaHR0cHM6Ly9hcGkuYnJpZ2h0c3BhY2UuY29tL2F1dGgvbG9yZXMubWFuYWdlIn0.PxS2jjOnSqS65xTEK0345qiynYRuaLfBh0hr6MKuWe2XOP7Z3t6x70VSM8o6PXnBMK2jJXFSf6lpl62cZpW5daal_9_YVJGGxC02__tWOAkfs61C_rHBqHNrJe8x2FSA1FiuPjBmi8Cqenf2d4VimA-UKCicuJ9HpI-5jBO5GgcZIEoUqSIAyHmFxk2fzZe43_RppxpM_LNAlMGss8pxtW2hJV-0iw3tc4l5vzYfHgLsa5aDXZsu4f8DZl0qBL4P4j07LVR0PLXPyjkCRfIyCgxUwvowJemgt9k7vMo5TwYiQs8zrOQHkRmCKO2nJiUhdTI3JuPcRCqq3Z6JhGtHsg";
		}

		internal static class ValidNoXsrfOneScope {
			internal const long Sub = 169;
			internal const string Tenantid = "00000000-0000-0000-0000-000000000000";
			internal const string Tenanturl = "http://lores.d2l";
			internal const long Exp = 1621858476;
			internal const string Iss = "https://api.d2l.com/auth";
			internal const string Scope = "https://api.brightspace.com/auth/lores.manage";

			internal const string Jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjE2OSwidGVuYW50dXJsIjoiaHR0cDovL2xvcmVzLmQybCIsInRlbmFudGlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwiZXhwIjoxNjIxODU4NDc2LCJpc3MiOiJodHRwczovL2FwaS5kMmwuY29tL2F1dGgiLCJzY29wZSI6Imh0dHBzOi8vYXBpLmJyaWdodHNwYWNlLmNvbS9hdXRoL2xvcmVzLm1hbmFnZSJ9.by4h32QfgzhEtE2j9brQiwzzz0jlhqaVNnWSWxBQ-BiE7NPB7A5DfDu-1S9TnCsjc4t1J4BOJUheS8hc-8BM2feu2I4ORupD-_5DJ1OhOsRBPpzRqi0fjbz91czThAkQK0VZI2SppSfKhiY-PwQqkAwDlMuinCPh5S8-KqLg0kpUQN6gl8IF6nS3IuslF481kLV4jOHbxbWEyDb9hwMzFJ0YxSIkgXq5AJH9Vldfe_wGOq0A1Q9vxh1prW8CkA-1mRsPO0KEdvmknW9hYS23i_otXkXGIPdHa2LSmczkW9_F4ZXYzoT0lLLtdSVLbQ1jvgY3F_J8-iSQGxzhJMdudw";
		}
	}
}
