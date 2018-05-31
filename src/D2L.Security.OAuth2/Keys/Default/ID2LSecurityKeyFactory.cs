﻿using System;
using Microsoft.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Keys.Default {
	internal interface ID2LSecurityKeyFactory {

		D2LSecurityKey Create( Func<Tuple<AsymmetricSecurityKey, IDisposable>> keyFactory );

	}
}
