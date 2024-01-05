package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

const START_YEAR = 2013
const END_YEAR = 2013
const BASE_URL = "https://www.malware-traffic-analysis.net"

func main() {
	for y := START_YEAR; y <= END_YEAR; y++ {

		sub_url, _ := url.JoinPath(BASE_URL, strconv.Itoa(y))

		res, err := http.Get(sub_url)

		if err != nil {
			log.Fatal(err)
		}

		doc, err := goquery.NewDocumentFromResponse(res)

		if err != nil {
			log.Fatal(err)
		}

		sub_dir := filepath.Join("res", strconv.Itoa(y))

		if _, err := os.Stat(sub_dir); os.IsNotExist(err) {
			// directory for a certain year does not exist
			if err := os.Mkdir(sub_dir, os.ModePerm); err != nil {
				fmt.Println(err)
			}
		}

		doc.Find("li .list_header").Each(func(i int, s *goquery.Selection) {
			link, _ := s.Attr("href")

			post_url, _ := url.JoinPath(sub_url, link)

			res, err := http.Get(post_url)

			if err != nil {
				log.Fatal(err)
			}

			post_main, err := goquery.NewDocumentFromResponse(res)

			if err != nil {
				log.Fatal(err)
			}

			article_name := post_main.Find("title").Text()
			article_name = strings.TrimPrefix(article_name, "Malware-Traffic-Analysis.net - ")
			post_dir := filepath.Join(sub_dir, article_name)

			post_main.Find("li .menu_link").Each(func(i int, s *goquery.Selection) {
				res_link, _ := s.Attr("href")

				if !strings.HasSuffix(res_link, ".zip") {
					return
				}

				if _, err := os.Stat(post_dir); os.IsNotExist(err) {
					// directory for a certain post entity does not exist
					if err := os.Mkdir(post_dir, os.ModePerm); err != nil {
						fmt.Println(err)
					}
				}

				file_url, err := url.JoinPath(post_url, res_link)

				if err != nil {
					log.Fatal(err)
				}

				file_path := filepath.Join(post_dir, "associated files", res_link)

				if strings.HasSuffix(res_link, ".pcap.zip") { // packet data
					file_path = filepath.Join(post_dir, "packet", res_link)
					fmt.Printf("--Packet : %s\n", res_link)
				} else { // other materials
					fmt.Printf("--Others : %s\n", res_link)
				}

				DownloadFile(file_path, file_url)
			})

			fmt.Printf("Reading posts in %d : %d (%s)\n", y, i, article_name)
		})

		fmt.Println("")
	}
}

// DownloadFile will download from a given url to a file. It will
// write as it downloads (useful for large files).
func DownloadFile(path string, url string) {
	err := os.MkdirAll(filepath.Dir(path), 0770)

	if err != nil {
		log.Fatal(err)
	}

	// Create the file
	out, err := os.Create(path)

	if err != nil {
		log.Fatal(err)
	}

	defer out.Close()

	// Get the data
	resp, err := http.Get(url)

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)

	if err != nil {
		log.Fatal(err)
	}
}
