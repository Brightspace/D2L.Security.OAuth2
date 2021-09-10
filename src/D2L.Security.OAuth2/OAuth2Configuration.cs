using System;

namespace D2L.Security.OAuth2 {
	public sealed class OAuth2Configuration {
		/// <summary>
		/// When a new key is created we try to avoid using it immediately so
		/// that caches can expire.
		/// </summary>
		public TimeSpan KeyTimeUntilUse { get; init; }
			= TimeSpan.FromHours( 1 );

		/// <summary>
		/// We rotate keys before they expire so that any tokens signed by the
		/// key will become invalid before it expires.
		/// </summary>
		public TimeSpan KeyRotationBuffer { get; init; }
			= TimeSpan.FromDays( 7 );

		/// <summary>
		/// The total lifetime keys we generate.
		/// </summary>
		public TimeSpan KeyLifetime { get; init; }
			= TimeSpan.FromDays( 30 );

		/// <summary>
		/// Check that the settings make sense and enforce some minimums to
		/// make reasoning about details around rotation easier.
		/// </summary>
		internal void CheckSanity() {
			if( KeyTimeUntilUse.TotalHours < 1 ) {
				throw new Exception( "KeyTimeUntilUse is too short" );
			}

			if( KeyTimeUntilUse >= KeyLifetime ) {
				throw new Exception( "KeyTimeUntilUse is too long" );
			}

			if( KeyRotationBuffer.TotalHours < 1 ) {
				throw new Exception( "KeyRotationBuffer is too short" );
			}

			if( KeyRotationBuffer >= KeyLifetime ) {
				throw new Exception( "KeyRotationBuffer is too long" );
			}

			if( KeyLifetime.TotalHours < 3 ) {
				throw new Exception( "KeyLifetime is too short" );
			}

			if( KeyLifetime.TotalDays > 365 ) {
				throw new Exception( "KeyLifetime is too long" );
			}

			if( (KeyLifetime - KeyRotationBuffer - KeyTimeUntilUse).TotalHours < 1 ) {
				throw new Exception( "KeyLifetime should be long enough to avoid rotations for at least an hour" );
			}
		}
	}
}
