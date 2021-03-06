﻿using System;
using System.Security.Cryptography;
using System.Threading;
using Microsoft.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Keys.Default {

	internal sealed partial class D2LSecurityToken : SecurityKey {

		// This ThreadLocal is used as most implementations of the SecurityKeys
		// such as RSACryptoServiceProvider are not thread-safe
		// This allows us to share the D2LSecurityToken across threads, while still
		// respecting the thread safety warning of those implemtnations
		private readonly ThreadLocal<Tuple<AsymmetricSecurityKey, IDisposable>> m_key;

		public D2LSecurityToken(
			string id,
			DateTimeOffset validFrom,
			DateTimeOffset validTo,
			Func<Tuple<AsymmetricSecurityKey, IDisposable>> keyFactory
		) {
			if( validFrom >= validTo ) {
				throw new ArgumentException( "validFrom must be before validTo" );
			}

			Id = id;
			ValidFrom = validFrom;
			ValidTo = validTo;

			m_key = new ThreadLocal<Tuple<AsymmetricSecurityKey, IDisposable>>(
				valueFactory: () => {
					var result = keyFactory();
					result.Item1.KeyId = KeyId;
					return result;
				},
				trackAllValues: true
			);
		}

		public string Id { get; }
		public DateTimeOffset ValidFrom { get; }
		public DateTimeOffset ValidTo { get; }

		public SigningCredentials GetSigningCredentials() {
			var signingCredentials = new SigningCredentials(
				this,
				GetSignatureAlgorithm()
			) {
				CryptoProviderFactory = new D2LCryptoProviderFactory()
			};

			return signingCredentials;
		}

		private string GetSignatureAlgorithm() {
			switch( GetKey() ) {
				case ECDsaSecurityKey ecDsaSecurityKey:
					return ecDsaSecurityKey.KeySize switch {
						256 => SecurityAlgorithms.EcdsaSha256,
						384 => SecurityAlgorithms.EcdsaSha384,
						521 => SecurityAlgorithms.EcdsaSha512,
						_ => throw new NotSupportedException(),
					};

				case RsaSecurityKey rsaSecurityKey:
					return SecurityAlgorithms.RsaSha256;

				default:
					throw new NotSupportedException();
			}
		}

		public JsonWebKey ToJsonWebKey() {
			switch( GetKey() ) {
				case ECDsaSecurityKey eCDsaSecurityKey:
					ECParameters parameters = eCDsaSecurityKey.ECDsa.ExportParameters( includePrivateParameters: false );
					return new EcDsaJsonWebKey( Id, ValidTo, parameters );

				case RsaSecurityKey rsaSecurityKey:
					var csp = rsaSecurityKey.Rsa;
					RSAParameters p = csp.ExportParameters( includePrivateParameters: false );
					return new RsaJsonWebKey( Id, ValidTo, p );

				default:
					throw new NotImplementedException();
			}
		}

		internal AsymmetricSecurityKey GetKey() => m_key.Value.Item1;

		public override int KeySize => GetKey().KeySize;

		public override string KeyId => Id;

	}
}
