using System;
using System.Threading;
using System.Threading.Tasks;

namespace D2L.Security.AuthTokenValidation.Utilities {
	internal static class AsyncHelper {

		private static readonly TaskFactory MyTaskFactory = new TaskFactory( 
			CancellationToken.None, 
			TaskCreationOptions.None, 
			TaskContinuationOptions.None, 
			TaskScheduler.Default 
			);
		
		internal static TResult RunSync<TResult>( Func<Task<TResult>> func ) {
			return MyTaskFactory.StartNew( func ).Unwrap().GetAwaiter().GetResult();
		}
	}
}
