﻿using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using static D2L.CodeStyle.Annotations.Objects;

namespace D2L.Security.OAuth2.Scopes {

	/// <summary>
	/// Strongly-typed represenation of a scope. Scopes are used to restrict access of clients to authorized 
	/// functionality. Scope strings have the following representation: {group}:{resource}:{permission[,permission]*}.
	/// Wildcards can be used in any of the three segments.
	/// </summary>
	[Immutable]
	public sealed class Scope {

		private readonly string m_group;
		private readonly string m_resource;
		private readonly ImmutableArray<string> m_permissions;

		/// <summary>
		/// Constructs a new <see cref="Scope"/>
		/// </summary>
		/// <param name="group">The first part of a scope, which represents a group of resources. It is the 
		/// highest level part of a scope definition. Usually this will be the name of a service.</param>
		/// <param name="resource">The second part of a scope, which represents a resource which a 
		/// permission applies to. Examples: objectives, registries.</param>
		/// <param name="permission">The third part of a scope, which represents a permission. It is the 
		/// lowest level part of a scope definition. Examples: read, write.</param>
		public Scope( string group, string resource, string permission )
			: this( group, resource, new[] { permission } ) {
		}

		/// <summary>
		/// Constructs a new <see cref="Scope"/>
		/// </summary>
		/// <param name="group">The first part of a scope, which represents a group of resources. It is the 
		/// highest level part of a scope definition. Usually this will be the name of a service.</param>
		/// <param name="resource">The second part of a scope, which represents a resource which a 
		/// permission applies to. Examples: objectives, registries.</param>
		/// <param name="permissions">The third part of a scope, which represents a set of permissions. It is the 
		/// lowest level part of a scope definition. Examples: read, write.</param>
		public Scope( string group, string resource, string[] permissions ) {
			m_group = group;
			m_resource = resource;
			m_permissions = permissions.OrderBy( x => x ).ToImmutableArray();
		}

		/// <summary>
		/// The first part of a scope, which represents a group of resources. It is the highest 
		/// level part of a scope definition. Usually this will be the name of a service.
		/// </summary>
		public string Group {
			get { return m_group; }
		}

		/// <summary>
		/// The second part of a scope, which represents a resource which a permission applies to. 
		/// Examples: objectives, registries.
		/// </summary>
		public string Resource {
			get { return m_resource; }
		}

		/// <summary>
		/// The third part of a scope, which represents a set of permissions. It is the lowest 
		/// level part of a scope definition. Examples: read, write.
		/// </summary>
		public IReadOnlyList<string> Permissions {
			get { return m_permissions; }
		}

		/// <summary>
		/// Converts a <see cref="Scope"/> to a string in the following format:
		/// {group}:{resource}:{permission[,permission]*}
		/// </summary>
		/// <returns>A scope in the format {group}:{resource}:{permission[,permission]*}</returns>
		public override string ToString() {
			var permissionsString = string.Join( ",", m_permissions );
			var result = string.Join( ":", m_group, m_resource, permissionsString );
			return result;
		}

		/// <summary>
		/// Compares two <see cref="Scope"/> objects for equality.
		/// </summary>
		/// <returns>True if they contain the same scopes in the same order, otherwise false</returns>
		public override bool Equals( object obj ) {
			if( ReferenceEquals( this, obj ) ) {
				return true;
			}

			var otherScope = obj as Scope;
			if( otherScope == null ) {
				return false;
			}

			return this.GetHashCode() == otherScope.GetHashCode();
		}

		/// <summary>
		/// Returns the hashcode
		/// </summary>
		public override int GetHashCode() {
			return this.ToString().GetHashCode();
		}

		/// <summary>
		/// Tries to parse a scope pattern into a <see cref="Scope"/>.
		/// </summary>
		/// <param name="scopePattern">The scope pattern in the form of
		/// group:resource:permission[,permission].</param>
		/// <param name="scope">asdf</param>
		/// <returns>true if the scope pattern was properly
		/// parsed, otherwise false</returns>
		/// <example>
		/// groupA:*:*                  => Full access to all groupA resources
		/// groupA:resourceX:*          => Full access to resourceX in groupA
		/// groupA:resourceX:read       => Read only for resourceX in groupA
		/// groupA:*:read               => Read only for all resources in groupA
		/// groupA:*:create             => Create only for all resources in groupA
		/// groupA:*:read,create,update => Read, create, or update for all resources in groupA
		/// *:*:*                       => Full access to all resources in all groups
		/// *:*:read                    => Read only for all resources in all groups
		/// </example>
		public static bool TryParse( string scopePattern, out Scope scope ) {
			try {
				scope = Parse( scopePattern );
				return true;
			} catch {
				scope = null;
				return false;
			}
		}

		/// <summary>
		/// Parses a scope pattern into a <see cref="Scope"/>.
		/// </summary>
		/// <param name="scopePattern">The scope pattern in the form of
		/// group:resource:permission[,permission]*.</param>
		/// <returns>If the scope is formatted correctly, returns the <see cref="Scope"/> object</returns>
		/// <exception cref="ArgumentException"></exception>
		public static Scope Parse( string scopePattern ) {
			if( String.IsNullOrWhiteSpace( scopePattern ) ) {
				throw new ArgumentException( "Expected a non-empty string", nameof( scopePattern ) );
			}

			string[] scopeParts = scopePattern.Split( ":".ToCharArray(), StringSplitOptions.RemoveEmptyEntries );
			if( scopeParts.Length != 3 || scopeParts.Any( String.IsNullOrWhiteSpace ) ) {
				throw new ArgumentException( "Expected 3 scope parts", nameof( scopePattern ) );
			}

			string[] permissionParts = scopeParts[ 2 ].Split( ",".ToCharArray(), StringSplitOptions.RemoveEmptyEntries );
			if( permissionParts.Length < 1 ) {
				throw new ArgumentException( "Expected one or more permissions in permission part", nameof( scopePattern ) );
			}

			return new Scope( scopeParts[ 0 ], scopeParts[ 1 ], permissionParts );
		}

	}

}
