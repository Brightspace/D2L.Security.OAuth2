using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Keys.Default {
	partial class EcDsaJsonWebKey {

		private static class ECParametersHelper {

			public static ECParameters FromJose( string curve, byte[] x, byte[] y ) {
				return new ECParameters {
					Curve = curve switch {
						"P-256" => ECCurve.NamedCurves.nistP256,
						"P-384" => ECCurve.NamedCurves.nistP384,
						"P-521" => ECCurve.NamedCurves.nistP521,
						_ => throw new Exception( $"Unknown curve: {curve}" ),
					},
					Q = new ECPoint {
						X = x,
						Y = y,
					},
				};
			}

			public static ( string curve, byte[] x, byte[] y ) ToJose( ECParameters parameters ) {
				if( !parameters.Curve.IsNamed ) {
					throw new Exception( $"Expected named curve: { new { parameters.Curve.CurveType, parameters.Curve.A, parameters.Curve.B, parameters.Curve.G } }" );
				}

				string curve = parameters.Curve.Oid.FriendlyName switch {
					"ECDSA_P256" => "P-256",
					"nistP256" => "P-256",

					"ECDSA_P384" => "P-384",
					"nistP384" => "P-384",

					"ECDSA_P521" => "P-521",
					"nistP521" => "P-521",

					_ => throw new Exception( $"Unknown curve: { parameters.Curve.Oid.FriendlyName }" ),
				};

				return (
					curve,
					x: parameters.Q.X,
					y: parameters.Q.Y
				);
			}

		}

	}
}
