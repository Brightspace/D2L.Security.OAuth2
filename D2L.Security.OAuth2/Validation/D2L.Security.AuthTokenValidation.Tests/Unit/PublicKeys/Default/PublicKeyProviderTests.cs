using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Unit.PublicKeys.Default {
	
	[TestFixture]
	internal sealed class PublicKeyProviderTests {

		[Test]
		public void Get_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void Get_WrongJsonWebKeyCount_Throws() {
			Assert.Inconclusive();
		}

		[Test]
		public void Get_InvalidKeyType_Throws() {
			Assert.Inconclusive();
		}

		[Test]
		public void Get_WrongX5CEntryCount_Throws() {
			Assert.Inconclusive();
		}
	}
}
