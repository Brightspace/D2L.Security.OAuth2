using System;
using System.Text;

namespace D2L.Security.OAuth2.TestUtilities {
	internal static class CookieHeaderMaker {
		internal static string MakeCookieHeader( params Tuple<string, string>[] cookies ){
			StringBuilder builder = new StringBuilder();
			foreach( Tuple<string, string> cookie in cookies ){
				builder.Append( cookie.Item1 );
				builder.Append( "=" );
				builder.Append( cookie.Item2 );
				builder.Append( "; " );
			}

			string result = builder.ToString();
			result = result.Substring( 0, result.Length - 2 );

			return result;
		}
	}
}
