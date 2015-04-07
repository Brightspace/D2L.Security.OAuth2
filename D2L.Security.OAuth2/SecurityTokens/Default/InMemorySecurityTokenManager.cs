using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.SecurityTokens.Default {
	/// <summary>
	/// An in-memory data-store for SecurityTokens
	/// </summary>
	/// <remarks>
	/// This should only be used for tests or prototyping. One catch (due to C#
	/// not having awesome features like C++'s "const SecurityToken&" is that
	/// any caller could mutate the returned token from a Get and corrupt the
	/// storage (or, in this implementation, get the List of SecurityTokens 
	/// and go wild.) Callers should ensure this doesn't happen.
	/// </remarks>
	[Obsolete("Only use this implementation for prototyping and tests.")]
	internal sealed class InMemorySecurityTokenManager : ISecurityTokenManager, IDisposable {
		private readonly List<D2LSecurityToken> m_tokens = new List<D2LSecurityToken>();

		Task<D2LSecurityToken> ISecurityTokenManager.GetLatestTokenAsync() {
			return Task.FromResult(
				m_tokens
					.OrderBy( t => t.ValidTo )
					.FirstOrDefault() );
		}

		Task<IEnumerable<D2LSecurityToken>> ISecurityTokenManager.GetAllTokens() {
			IEnumerable<D2LSecurityToken> result
				= new ReadOnlyCollection<D2LSecurityToken>( m_tokens );

			return Task.FromResult( result );
		}

		Task ISecurityTokenManager.SaveAsync( D2LSecurityToken token ) {
			if( !token.HasPrivateKey() ) {
				throw new InvalidOperationException(
					"Storing tokens without private keys is not supported by this implementation of ISecurityTokenManager"	 );
			}
			m_tokens.Add( token );
			return Task.Delay( 0 );
		}

		Task ISecurityTokenManager.DeleteAsync( Guid id ) {
			int index = m_tokens.FindIndex( t => t.KeyId == id );
			m_tokens[ index ].Dispose();
			m_tokens.RemoveAt( index );
			return Task.Delay( 0 );
		}

		public void Dispose() {
			foreach( var token in m_tokens ) {
				token.Dispose();
			}
			m_tokens.Clear();
		}
	}
}
