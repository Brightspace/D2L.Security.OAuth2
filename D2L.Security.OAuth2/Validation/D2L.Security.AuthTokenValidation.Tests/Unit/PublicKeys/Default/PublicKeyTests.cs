using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Unit.PublicKeys.Default {
	
	[TestFixture]
	internal sealed class PublicKeyTests {

		[Test]
		public void Constructor_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void Constructor_WrongNumberOfSecurityKeys_Throws() {
			Assert.Inconclusive();
		}

		[Test]
		public void Constructor_NullSecurityToken_Throws() {
			Assert.Inconclusive();
		}

		[Test]
		public void Constructor_NullIssuer_Throws() {
			Assert.Inconclusive();
		}

		[Test]
		public void Constructor_SecurityKeysCollectionNull_Throws() {
			Assert.Inconclusive();
		}
	}
}
