using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2 {
	internal static class TaskExtensions {

		public static ConfiguredTaskAwaitable<T> SafeAsync<T>( this Task<T> @this ) {
			return @this.ConfigureAwait( continueOnCapturedContext: false );
		}

		public static ConfiguredTaskAwaitable SafeAsync( this Task @this ) {
			return @this.ConfigureAwait( continueOnCapturedContext: false );
		}

		public static T CallSync<T>( this Task<T> @this ) {
			return @this.SafeAsync().GetAwaiter().GetResult();
		}

		public static void CallSync( this Task @this ) {
			@this.SafeAsync().GetAwaiter().GetResult();
		}

	}
}
