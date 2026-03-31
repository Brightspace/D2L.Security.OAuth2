using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace D2L.Security.OAuth2.Scopes;

public static class ScopeSimplifier {
	public static IEnumerable<Scope> Simplify( this IEnumerable<Scope> @this ) {
		if( @this.Count() == 1 ) {
			return @this;
		}

		var flatScopes = @this.Flatten().Distinct().OrderBy( s => s.ToString() );
		var set = new HashSet<string>( flatScopes.Select( s => s.ToString() ) );

		var uniqueScopes = flatScopes.Where( s => !set.HasBroaderVariant( s ) );

		var tree = new Dictionary<string, IDictionary<string, IList<string>>>();
		foreach( var scope in uniqueScopes ) {
			if( !tree.ContainsKey( scope.Group ) ) {
				tree.Add( scope.Group, new Dictionary<string, IList<string>>() );
			}

			var group = tree[ scope.Group ];

			if( !group.ContainsKey( scope.Resource ) ) {
				group.Add( scope.Resource, new List<string>() );
			}

			var resource = group[ scope.Resource ];

			resource.Add( scope.Permissions[ 0 ] );
		}

		return tree
			.SelectMany(
				group => group.Value.Select(
					resource => new Scope( group.Key, resource.Key, resource.Value.ToArray() )
				)
			);
	}

	private static string FormatScope( string group, string resource, string permission ) {
		return string.Format( "{0}:{1}:{2}", group, resource, permission, CultureInfo.InvariantCulture );
	}

	private static bool HasBroaderVariant( this HashSet<string> set, Scope scope ) {
		var scopeAsString = scope.ToString();

		if( set.VariantIsDifferentAndPresent( scopeAsString, FormatScope( "*", "*", "*" ) ) ) {
			return true;
		}

		if( set.VariantIsDifferentAndPresent( scopeAsString, FormatScope( "*", "*", scope.Permissions[0] ) ) ) {
			return true;
		}

		if( set.VariantIsDifferentAndPresent( scopeAsString, FormatScope( "*", scope.Resource, "*" ) ) ) {
			return true;
		}

		if( set.VariantIsDifferentAndPresent( scopeAsString, FormatScope( "*", scope.Resource, scope.Permissions[0] ) ) ) {
			return true;
		}

		if( set.VariantIsDifferentAndPresent( scopeAsString, FormatScope( scope.Group, "*", "*" ) ) ) {
			return true;
		}

		if( set.VariantIsDifferentAndPresent( scopeAsString, FormatScope( scope.Group, scope.Resource, "*" ) ) ) {
			return true;
		}

		if( set.VariantIsDifferentAndPresent( scopeAsString, FormatScope( scope.Group, "*", scope.Permissions[0] ) ) ) {
			return true;
		}

		return false;
	}

	private static bool VariantIsDifferentAndPresent( this HashSet<string> set, string scope, string variant ) {
		if( scope == variant ) {
			return false;
		}

		return set.Contains( variant );
	}

	private static IEnumerable<Scope> Flatten( this IEnumerable<Scope> @this ) {
		foreach( Scope scope in @this ) {
			if( scope.Permissions.Count == 1 ) {
				yield return scope;
				continue;
			}

			foreach( string permission in scope.Permissions ) {
				yield return new Scope( scope.Group, scope.Resource, permission );
			}
		}
	}
}