
type StatusCode =  401 | 403;

export class ResponseBuilder {

    static _sendResponse(res: any, statusCode: StatusCode, status: string, error: any) {
        
        return res.status(statusCode)
        .json({
            status: status,
            error: error,
        })
    }

    static forbidden(res: Response, code: StatusCode ,  error: string) {
        return ResponseBuilder._sendResponse(res, code, "Forbidden", error)
    }
}
