import requests

def getbookstoupdate(endpoint):
    params = {'isedited':0, 'isamended':0}
    response = requests.get(endpoint+"/books",params=params)
    return response.json()

def getbookdatafromopenlibrary(isbn):
    response = requests.get(f"https://openlibrary.org/isbn/{isbn}.json")
    print(response.status_code)
    if response.status_code == 404: return None
    return response.json()
    
if __name__ == '__main__':
    import argparse
    from time import sleep

    parser = argparse.ArgumentParser()
    parser.add_argument('--restserver', '-r', default='http://localhost', help='REST endpoint of objectstore')
    args = parser.parse_args()


# how are we going to do this w.o. a webserver?
#   prometheus = PrometheusMiddleware()

    running = True
    while running:
        # do something
        # for the healthcheck we might touch a file?
        books = getbookstoupdate(args.restserver)
        for book in books['data']:
            print(book['isbn'])
            print(getbookdatafromopenlibrary(book['isbn']))
        sleep(10)   # or we could run everything from cron?

