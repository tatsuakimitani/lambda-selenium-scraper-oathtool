# lambda-selenium-scraper-oathtool

## Serverless Framework install
```
(lambda-selenium-scraper-oathtool)$ sudo npm install -g serverless
```

## Chrome install
```
(lambda-selenium-scraper-oathtool)$ sh install.sh
```

## Python Library install
```
(lambda-selenium-scraper-oathtool)$ cd selenium-layer
(selenium-layer)$ pip3 install -t selenium/python/lib/python3.7/site-packages selenium
(selenium-layer)$ pip3 install -t oathtool/python/lib/python3.7/site-packages oathtool
(selenium-layer)$ pip3 install -t slacker/python/lib/python3.7/site-packages Slacker
```

## npm install for layer
```
(lambda-selenium-scraper-oathtool)$ cd selenium-layer
(selenium-layer)$ npm install
```

## layer deploy
```
(lambda-selenium-scraper-oathtool)$ cd selenium-layer
(selenium-layer)$ cp config/.env.tmpl config/.env
(selenium-layer)$ sls deploy
```

## npm install for Lambda
```
(lambda-selenium-scraper-oathtool)$ cd lambda
(lambda)$ npm install
```

## Lambda deploy
```
(lambda-selenium-scraper-oathtool)$ cd lambda
(lambda)$ cp config/.env.tmpl config/.env
(lambda)$ sls deploy
```
