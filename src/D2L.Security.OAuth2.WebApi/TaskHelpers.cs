using System.Threading.Tasks;

namespace D2L.Security.OAuth2 {
	internal static class TaskHelpers {
		/// <summary>
		/// Delete this once we have .NET 4.6+ and can use Task.CompletedTask 
		/// </summary>
		public static readonly Task CompletedTask = Task.FromResult( false );
	}
}
