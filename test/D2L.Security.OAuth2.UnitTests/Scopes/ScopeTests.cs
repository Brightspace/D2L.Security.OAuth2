using System;
using FluentAssertions;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Scopes {
	[TestFixture]
	internal sealed class ScopeTests {

		internal static TestCaseData[] InvalidScopeCases = new[] {
			new TestCaseData( null ).SetDescription( "Null" ),
			new TestCaseData( "" ).SetDescription( "Empty" ),
			new TestCaseData( "g" ).SetDescription( "One part" ),
			new TestCaseData( "g:r" ).SetDescription( "Two parts" ),
			new TestCaseData( "g:" ).SetDescription( "Two parts, first is empty" ),
			new TestCaseData( ":r" ).SetDescription( "Two parts, second is empty" ),
			new TestCaseData( ":" ).SetDescription( "Two parts, both are empty" ),
			new TestCaseData( "g:r:" ).SetDescription( "Three parts, first is empty" ),
			new TestCaseData( "g::p" ).SetDescription( "Three parts, second is empty" ),
			new TestCaseData( ":r:p" ).SetDescription( "Three parts, third is empty" ),
			new TestCaseData( "g::" ).SetDescription( "Three parts, last two are empty" ),
			new TestCaseData( ":r:" ).SetDescription( "Three parts, first and last are empty" ),
			new TestCaseData( "::p" ).SetDescription( "Three parts, first two are empty" ),
			new TestCaseData( "::" ).SetDescription( "Three parts, all are empty" ),
			new TestCaseData( "g:r:," ).SetDescription( "Three parts, invalid permissions" )
		};

		[TestCaseSource( nameof( InvalidScopeCases ) )]
		public void InvalidScopePattern_IsNotParsed( string scopePattern ) {
			Scope scope = null;
			bool isParsed = Scope.TryParse( scopePattern, out scope );

			isParsed.Should().BeFalse();
		}

		[TestCaseSource( nameof( InvalidScopeCases ) )]
		public void ScopeParse_InvalidScopePattern_Throws( string scopePattern ) {
			Assert.That( () => Scope.Parse( scopePattern ), Throws.ArgumentException );
		}


		internal static TestCaseData[] ValidScopeScopes = new[] {
			new TestCaseData( "g:r:p", "g", "r", new[] { "p" } ).SetDescription( "Single permission" ),
			new TestCaseData( "g:r:p1,p2", "g", "r", new[] { "p1", "p2" } ).SetDescription( "Multiple permissions" )
		};

		[TestCaseSource( nameof( ValidScopeScopes ) )]
		public void ValidScopePattern_IsProperlyParsed(
			string scopePattern,
			string group,
			string resource,
			string[] permissions ) {

			Scope scope = null;
			bool isParsed = Scope.TryParse( scopePattern, out scope );

			isParsed.Should().BeTrue();
			scope.Group.Should().Be( group );
			scope.Resource.Should().Be( resource );
			CollectionAssert.AreEquivalent( permissions, scope.Permissions );
		}

		[TestCaseSource( nameof( ValidScopeScopes ) )]
		public void ScopeParse_ValidScopePattern_Returns(
			string scopePattern,
			string group,
			string resource,
			string[] permissions
		) {
			Scope scope = Scope.Parse( scopePattern );
			Assert.That( scope.Group, Is.EqualTo( group ) );
			Assert.That( scope.Resource, Is.EqualTo( resource ) );
			Assert.That( scope.Permissions, Is.EquivalentTo( permissions ) );
		}
	}
}
