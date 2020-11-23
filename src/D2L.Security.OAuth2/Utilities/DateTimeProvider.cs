using System;
using static D2L.CodeStyle.Annotations.Objects;

namespace D2L.Security.OAuth2.Utilities {

	[Immutable]
	internal sealed class DateTimeProvider : IDateTimeProvider {

		internal static readonly IDateTimeProvider Instance = new DateTimeProvider();

		public DateTimeOffset UtcNow {
			get { return DateTimeOffset.UtcNow; }
		}
	}
}
