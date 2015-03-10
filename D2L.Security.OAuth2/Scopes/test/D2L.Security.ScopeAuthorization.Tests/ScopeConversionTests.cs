using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using NUnit.Framework;

namespace D2L.Security.ScopeAuthorization.Tests {

	internal sealed class ScopeConversionTests {

		[TestCase( null, Description = "Null" )]
		[TestCase( "", Description = "Empty" )]
		[TestCase( "g", Description = "One part" )]
		[TestCase( "g:r", Description = "Two parts" )]
		[TestCase( "g:", Description = "Two parts, first is empty" )]
		[TestCase( ":r", Description = "Two parts, second is empty" )]
		[TestCase( ":", Description = "Two parts, both are empty" )]
		[TestCase( "g:r:", Description = "Three parts, first is empty" )]
		[TestCase( "g::p", Description = "Three parts, second is empty" )]
		[TestCase( ":r:p", Description = "Three parts, third is empty" )]
		[TestCase( "g::", Description = "Three parts, last two are empty" )]
		[TestCase( ":r:", Description = "Three parts, first and last are empty" )]
		[TestCase( "::p", Description = "Three parts, first two are empty" )]
		[TestCase( "::", Description = "Three parts, all are empty" )]
		[TestCase( "g:r:,", Description = "Three parts, invalid permissions" )]
		public void InvalidScopePattern_Throws( string scopePattern ) {

			scopePattern.Invoking( s => Scope.FromString( s ) )
				.ShouldThrow<ArgumentException>();
		}

		[TestCase( "g:r:p", "g", "r", new[] { "p" }, Description = "Single permission" )]
		[TestCase( "g:r:p1,p2", "g", "r", new[] { "p1", "p2" }, Description = "Multiple permissions" )]
		public void ValidScopePattern_ReturnsScope(
			string scopePattern,
			string group,
			string resource,
			string[] permissions ) {

			var scope = Scope.FromString( scopePattern );

			scope.Group.Should().Be( group );
			scope.Resource.Should().Be( resource );
			scope.Permissions.ShouldAllBeEquivalentTo( permissions );
		}

	}

}
