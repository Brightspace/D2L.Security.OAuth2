using System;
using static D2L.CodeStyle.Annotations.Objects;

namespace D2L.Security.OAuth2.Utilities {

	[Immutable]
	internal interface IDateTimeProvider {
		DateTime UtcNow { get; }
	}
}
