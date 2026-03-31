using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Scopes;

[TestFixture]
internal sealed class ScopeSimplifierTests {
	[TestCase( "foo:bar:baz", "foo:bar:baz", TestName = "Should map single scope simply" )]
	[TestCase( "foo:bar:baz foo:bar:baz", "foo:bar:baz", TestName = "Should remove a simple duplicate" )]
	[TestCase( "foo:bar:d,c", "foo:bar:c,d", TestName = "Should alphabetize permissions" )]
	[TestCase( "foo:bar:baz foo:bar:quux", "foo:bar:baz,quux", TestName = "Should combine permissions of single resource" )]
	[TestCase( "foo:bar:baz,foozle foo:bar:baz,quux", "foo:bar:baz,foozle,quux", TestName = "Should remove duplicates when combining permissions" )]
	[TestCase( "foo:bar:baz,foozle foo:bar:baz,quux foo:bar:*", "foo:bar:*", TestName = "Should simplify to wildcard permission if present" )]
	[TestCase( "foo:bar:baz foo:quux:baz", "foo:bar:baz foo:quux:baz", TestName = "Should map multi resource simply" )]
	[TestCase( "foo:quux:baz foo:bar:baz", "foo:bar:baz foo:quux:baz", TestName = "Should alphabetize multi resource" )]
	[TestCase( "foo:bar:baz foo:quux:puppy foo:bar:foozle, foo:quux:baz", "foo:bar:baz,foozle foo:quux:baz,puppy", TestName = "Should combine permissions of individual resources" )]
	[TestCase( "foo:bar:baz foo:quux:baz foo:bar:baz", "foo:bar:baz foo:quux:baz", TestName = "Should remove duplicates with multiple resources" )]
	[TestCase( "foo:bar:baz,foozle foo:quux:baz foo:*:baz", "foo:*:baz foo:bar:foozle", TestName = "Should use wildcard resource permissions if present" )]
	[TestCase( "foo:bar:baz quux:foozle:puppy", "foo:bar:baz quux:foozle:puppy", TestName = "Should map multi group simply" )]
	[TestCase( "quux:foozle:puppy foo:bar:baz", "foo:bar:baz quux:foozle:puppy", TestName = "Should alphabetize multi group" )]
	[TestCase( "foo:bar:baz quux:foozle:puppy foo:bar:kitty quux:foozle:duck", "foo:bar:baz,kitty quux:foozle:duck,puppy", TestName = "Should combine permissions of individual groups/resources" )]
	[TestCase( "foo:bar:baz quux:foozle:puppy foo:bar:baz", "foo:bar:baz quux:foozle:puppy", TestName = "Should remove duplicates with multiple groups" )]
	[TestCase( "foo:bar:baz,kitty quux:bar:puppy,baz *:bar:baz", "*:bar:baz foo:bar:kitty quux:bar:puppy", TestName = "Should use wildcard group permissions if present" )]
	[TestCase( "foo:bar:baz,kitty quux:foozle:puppy,baz *:*:baz", "*:*:baz foo:bar:kitty quux:foozle:puppy", TestName = "Should use wildcard group permissions if present (2)" )]
	[TestCase( "foo:bar:baz,kitty quux:bar:puppy,baz *:*:*", "*:*:*", TestName = "Super-scope should be super-simple" )]
	public void Test( string input, string expected ) {
		Assert.That(
			expected,
			Is.EqualTo( string.Join( " ", ScopeSimplifier.Simplify( input.Split( ',' ).Select( Scope.Parse ) ) ) )
		);
	}
}
