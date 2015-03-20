using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Linq;
using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.PublicKeys.Default;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Unit.PublicKeys.Default {
	
	[TestFixture]
	internal sealed class PublicKeyTests {

		[Test]
		public void Constructor_Success() {
			Mock<SecurityKey> securityKey = new Mock<SecurityKey>();
			SecurityToken securityToken = MakeSecurityTokenMock( securityKey.Object );

			IPublicKey publicKey = new PublicKey( securityToken, "dummyissuer" );
			Assert.AreEqual( securityKey.Object, publicKey.SecurityKey );
		}

		[Test]
		public void Constructor_WrongNumberOfSecurityKeys_Zero_Throws() {
			SecurityToken securityToken = MakeSecurityTokenMock();
			Assert.Throws<Exception>( () => new PublicKey( securityToken, "dummyissuer" ) );
		}

		[Test]
		public void Constructor_WrongNumberOfSecurityKeys_Many_Throws() {
			SecurityToken securityToken = MakeSecurityTokenMock(
				new Mock<SecurityKey>().Object,
				new Mock<SecurityKey>().Object
				);

			Assert.Throws<Exception>( () => new PublicKey( securityToken, "dummyissuer" ) );
		}

		[Test]
		public void Constructor_NullSecurityToken_Throws() {
			SecurityToken securityToken = null;
			Assert.Throws<ArgumentException>( () => new PublicKey( securityToken, "dummyissuer" ) );
		}

		[Test]
		public void Constructor_NullIssuer_Throws() {
			Mock<SecurityToken> securityTokenMock = new Mock<SecurityToken>();
			Assert.Throws<ArgumentException>( () => new PublicKey( securityTokenMock.Object, null ) );
		}

		[Test]
		public void Constructor_SecurityKeysCollectionNull_Throws() {
			Mock<SecurityToken> securityTokenMock = new Mock<SecurityToken>();
			ReadOnlyCollection<SecurityKey> securityKeys = null;
			securityTokenMock.SetupGet( x => x.SecurityKeys ).Returns( securityKeys );

			Assert.Throws<ArgumentException>( () => new PublicKey( securityTokenMock.Object, "dummyissuer" ) );
		}

		private SecurityToken MakeSecurityTokenMock( params SecurityKey[] keys ) {
			IList<SecurityKey> securityKeyList = new List<SecurityKey>() {
				new Mock<SecurityKey>().Object,
				new Mock<SecurityKey>().Object
			};
			Mock<SecurityToken> securityTokenMock = new Mock<SecurityToken>();
			ReadOnlyCollection<SecurityKey> securityKeys = new ReadOnlyCollection<SecurityKey>( keys.ToList() );
			securityTokenMock.SetupGet( x => x.SecurityKeys ).Returns( securityKeys );

			return securityTokenMock.Object;
		}
	}
}
