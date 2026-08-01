use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::rc::Rc;

/// Rejects any request whose `X-API-Key` header doesn't match the configured key.
pub struct ApiKeyAuth {
    expected_key: Rc<String>,
}

impl ApiKeyAuth {
    pub fn new(expected_key: String) -> Self {
        Self {
            expected_key: Rc::new(expected_key),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for ApiKeyAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = ApiKeyAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ApiKeyAuthMiddleware {
            service,
            expected_key: self.expected_key.clone(),
        }))
    }
}

pub struct ApiKeyAuthMiddleware<S> {
    service: S,
    expected_key: Rc<String>,
}

impl<S, B> Service<ServiceRequest> for ApiKeyAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let provided = req
            .headers()
            .get("X-API-Key")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        if provided.as_deref() == Some(self.expected_key.as_str()) {
            let fut = self.service.call(req);
            Box::pin(async move { fut.await.map(ServiceResponse::map_into_left_body) })
        } else {
            let (req, _) = req.into_parts();
            let response = HttpResponse::Unauthorized().finish().map_into_right_body();
            Box::pin(async move { Ok(ServiceResponse::new(req, response)) })
        }
    }
}
