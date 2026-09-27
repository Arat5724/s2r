import uvicorn
from review.main import recover_interrupted_jobs

if __name__ == '__main__':
    recover_interrupted_jobs()
    uvicorn.run('review.main:app', host='127.0.0.1', port=8020, access_log=False, server_header=False)
