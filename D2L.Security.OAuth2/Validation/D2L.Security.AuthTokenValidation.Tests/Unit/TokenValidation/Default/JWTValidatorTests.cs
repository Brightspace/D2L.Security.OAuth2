using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Unit.TokenValidation.Default {
	
	[TestFixture]
	internal sealed class JWTValidatorTests {

		private const int InvalidPermutationsCount = 16;
		private static object[] InvalidPermutationsCases;

		static JWTValidatorTests() {
			InvalidPermutationsCases = new object[InvalidPermutationsCount-1];
			for( int i = 0; i < InvalidPermutationsCount; i++ ) {
				if( i == InvalidPermutationsCount - 1 ) {
					// skip all true
					continue;
				}
				InvalidPermutationsCases[i] = new object[] { 
					(i & 1) == 1,
					(i & 2) == 2,
					(i & 4) == 4,
					(i & 8) == 8
				};
			}
		}

		[Test]
		public void Validate_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void Validate_ExpiredToken_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void Validate_InvalidIssuer_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void Validate_InvalidAlgorithm_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void Validate_InvalidTokenType_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		[TestCaseSource( "InvalidPermutationsCases" )]
		public void InvalidPermutation_Throws( 
			bool isAlgorithmValid, 
			bool isIssuerValid, 
			bool isTokenExpired, 
			bool isTokenTypeValid 
			) {

			Assert.Inconclusive();
		}
	}
}
