# D2L.Security.WebApiAuth

A library that implements Web API components for authenticating D2L services.

## How to use this library?

Web API exposes two main ways to intercept incoming requests, filters and message handlers. This library implements a message handler, which means that attribute routing will not work. The library assumes you have an instance of Web API's System.Web.Http.HttpConfiguration and are routing by calling `httpConfiguration.Routes.MapHttpRoute` to map routes by code.

The library is DI-ready. The types you need to use to register for DI are all public.

1) For the interface, register `D2L.Security.WebApiAuth.Handler.IAuthenticationMessageHandlerFactory` and for the concrete type, register `D2L.Security.WebApiAuth.Handler.Default.AuthenticationMessageHandlerFactory` with your DI framework of choice.
2) Inject `IAuthenticationMessageHandlerFactory` into the class which is doing your routing configuration.
3) Call IAuthenticationMessageHandlerFactory.Create to get a `DelegatingHandler`.
4) Call httpConfiguration.MapHttpRoute, being sure to pass in the `DelegatingHandler` as the `HttpMessageHandler` parameter.

## Why was a Web API message handler approach chosen over Web API filters?

Filters work via attributes. Attribute instances get created outside of DI framework's control, which makes it difficult for the attribute to get access to a request validator without relying on statics and heuristics, which inhibit testability. Routing by code makes services more testable because you can easily mock the behaviour.