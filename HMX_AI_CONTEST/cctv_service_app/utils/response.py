def format_response(data):
    return {
        "status": "success",
        "data": data
    }

def handle_error(message):
    return {
        "status": "error",
        "message": message
    }