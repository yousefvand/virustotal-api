# virustotal-api

[Virustotal API v2.0](https://developers.virustotal.com/v2.0/reference) wrapper class

## Install

```shell
npm i virustotal-api
```

## Example

```javascript
const VirusTotalApi = require('virustotal-api')
const virusTotal = new VirusTotalApi('<YOUR API KEY>')
const fs = require('fs')
const buffer = fs.readFileSync('./file.txt')
virusTotal.fileScan(buffer, 'file.txt')
  .then((response) => {
    let resource = response.resource
    // sometime later try:
    virusTotal.fileReport(resource)
      .then((result) => {
        console.log(result)
      })
  })
```

For more info please refer to [documentation](./docs/virus-total.md)