using System;

namespace D2L.Security.AuthTokenValidation {
	internal static class IDisposableExtensions {

		internal static void SafeDispose( this IDisposable me ) {
			if( me == null ){
				return;
			}
			try {
				me.Dispose();
			} catch {}
		}
	}
}
