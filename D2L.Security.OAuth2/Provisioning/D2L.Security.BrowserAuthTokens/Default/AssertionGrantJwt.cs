using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.BrowserAuthTokens.Default {

	[DataContract]
	internal sealed class Header {
		[DataMember]
		public string typ { get; set; }

		[DataMember]
		public string alg { get; set; }
	}
}
