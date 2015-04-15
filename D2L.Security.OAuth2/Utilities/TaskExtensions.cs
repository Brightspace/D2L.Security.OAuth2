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
	}
}