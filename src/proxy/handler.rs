use hudsucker::{
    hyper::{Request, Response},
    Body, HttpContext, HttpHandler, RequestOrResponse,
};
use tracing::debug;

#[derive(Clone)]
pub struct LogHandler;

impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        debug!("{:?}", req.uri());
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        debug!("{:?}", res.status());
        res
    }
}
