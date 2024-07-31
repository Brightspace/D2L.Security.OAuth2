using System;

namespace D2L.Security.OAuth2 {
	internal static class SystemUriExtensions {

		public static Uri RelativePathAsNonLeaf( this Uri @this, string pathAddition ) {
			string path = @this.AbsolutePath;
			if( path[path.Length - 1] == '/' ) {
				return new Uri( @this, pathAddition );
			}

			return new Uri( new Uri( @this + "/" ), pathAddition );
		}

	}
}
