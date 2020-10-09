import requests
import json

def getbookstoupdate(endpoint):
    params = {'isedited':0, 'isamended':0}
    response = requests.get(endpoint+"/books",params=params)
    return response.json()

def getbookdatafromopenlibrary(isbn):
    print(isbn)
    response = requests.get(f"https://openlibrary.org/isbn/{isbn}.json")
    print(response.status_code)
    if response.status_code == 404: return None
    return response.json()

def getauthordatafromopenlibrary(authorid):
    print(authorid)
    response = requests.get(f"https://openlibrary.org/{authorid}.json")
    print(response.status_code)
    if response.status_code == 404: return None
    return response.json()

def getcoverfromopenlibrary(coverid):
    print(coverid)
    response = requests.get(f"https://covers.openlibrary.org/b/id/{coverid}-L.jpg")
    print(response.status_code)
    if response.status_code == 404: return None
    return response

def updatebook(endpoint, bookid, data):
    print(data)
    response = requests.put(f"{endpoint}/books/{bookid}", json=data)
    print(response)
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
            if book['isbn'] is not None and book['isbn'] != "":
                data = getbookdatafromopenlibrary(book['isbn'])
                print(data)
                if data is not None:
                    authordata = getauthordatafromopenlibrary(data['authors'][0]['key'])
                    print(authordata)
                    book['author'] = authordata['name']
                    book['publisher'] = data['publishers'][0]
                    book['title'] = data[ 'title']
                    print(updatebook(args.restserver, book['id'], book))
                    r = getcoverfromopenlibrary(data['covers'][0])
                    print('response',r)
                    with open('test.jpg','wb') as f:
                        f.write(r.content)
        sleep(10)   # or we could run everything from cron?

