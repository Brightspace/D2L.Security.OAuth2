using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.BrowserAuthTokens.Default;
using NUnit.Framework;

namespace D2L.Security.BrowserAuthTokens.Tests {
	
	[TestFixture]
	internal sealed class TemporaryTest {

		[Test]
		public void THROWAWAY_TEST() {
			AuthServerInvoker.TEST();
		}
	}
}
