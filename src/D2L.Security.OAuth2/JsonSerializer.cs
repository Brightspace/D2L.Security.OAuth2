namespace D2L.Security.OAuth2 {
	internal static class JsonSerializer {
#if NET6_0
		public static string Serialize<T>( T item ) =>
			System.Text.Json.JsonSerializer.Serialize( item );

		public static T Deserialize<T>( string json ) =>
			System.Text.Json.JsonSerializer.Deserialize<T>( json );
#else

		public static string Serialize<T>( T item ) =>
			Newtonsoft.Json.JsonConvert.SerializeObject( item );

		public static T Deserialize<T>( string json ) =>
			Newtonsoft.Json.JsonConvert.DeserializeObject<T>( json );
#endif
	}
}
